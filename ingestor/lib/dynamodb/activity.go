// Bounded write paths for roles and services.
//
// A role or service main item holds only fixed-size fields: identity,
// first/last seen, and running totals. Everything that grows with activity
// (per-event counts, per-service counts, resource accesses) lives in small
// activity items next to it, grouped so that one file touches few of them
// (see types.DynamoDBActivity). Every write is an UpdateItem: counters with
// ADD, identity with if_not_exists, and first/last seen only when they move.
// No path reads an item and writes the whole of it back, so a write costs
// what the small item weighs, not what the noun has accumulated.
//
// Items written before this layout carry the old unbounded attributes inline.
// Migration (see nounUpdate.migrate) copies them from a strongly consistent
// snapshot into separate "lc:"/"ld:"/"legacy_*" attributes of the activity
// items, then removes them only if they still equal that snapshot. Until the
// removal the legacy attributes stay authoritative and readers ignore the
// copies; after it, readers use the copies. A count is therefore read from
// exactly one place whichever side of the removal a read lands on.
package dynamodb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"golang.org/x/sync/errgroup"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// NounStore is the DynamoDB surface the bounded write paths use.
// *dynamodb.Client satisfies it.
type NounStore interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

const (
	// ActivityPartitionInfix joins a customer ID and a noun ID into the
	// partition holding the noun's activity items. Namespaces never contain
	// '#', so these partitions never collide with a customer's own.
	ActivityPartitionInfix = "#act#"

	ActivityEvent                = "evt"
	ActivityResourceAccess       = "ra"
	ActivityDeniedResourceAccess = "dra"
	ActivityDeniedEventAccess    = "dea"

	RoleSortAttr    = "arn"
	ServiceSortAttr = "event_source"

	// Counter attributes. Per-event counters are top-level number attributes
	// so one ADD creates or increments them without a parent map.
	AllowedCounterPrefix = "c:"
	DeniedCounterPrefix  = "d:"
	ServiceCountAttr     = "service_count"
	CountAttr            = "count"

	// Migrated legacy counts, written once with if_not_exists.
	LegacyAllowedCounterPrefix = "lc:"
	LegacyDeniedCounterPrefix  = "ld:"
	LegacyServiceCountAttr     = "legacy_service_count"
	LegacyCountAttr            = "legacy_count"

	// maxPartitionKeyBytes keeps activity partitions under DynamoDB's
	// 2048-byte partition key limit; longer noun IDs are hashed.
	maxPartitionKeyBytes = 1536
	// maxSortKeyBytes keeps activity sort keys under the 1024-byte limit.
	maxSortKeyBytes = 768
	// maxCountersPerUpdate and maxMigratedCountersPerUpdate keep update and
	// condition expressions under DynamoDB's 4 KB limit.
	maxCountersPerUpdate         = 100
	maxMigratedCountersPerUpdate = 40
	// maxMigrationAttempts bounds how often a migration restarts because its
	// source changed between the snapshot and the removal.
	maxMigrationAttempts = 3
	// activityConcurrency bounds in-flight activity updates per noun.
	activityConcurrency = 8
	// maxBoundAttempts bounds conditional retries of a main-item write.
	maxBoundAttempts = 4
)

// Attributes older ingestors kept inline. Each is migrated into activity
// items, derivable from them, or already held by the relations table.
var (
	LegacyRoleAttrs = []string{
		"services_used", "services_count", "resources_used", "resources_count",
		"top_event_names", "top_denied_event_names",
		"resource_accesses", "denied_resource_accesses", "denied_event_accesses",
	}
	LegacyServiceAttrs = []string{"roles_using", "resources_used", "top_event_names", "top_denied_event_names"}
)

// ActivityPartition is the partition key value of a noun's activity items.
func ActivityPartition(customerID, nounID string) string {
	p := customerID + ActivityPartitionInfix + nounID
	if len(p) <= maxPartitionKeyBytes {
		return p
	}
	return customerID + ActivityPartitionInfix + "sha256:" + digest(nounID)
}

func digest(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// ActivitySortKey is the sort key of one named activity item.
func ActivitySortKey(kind, name string) string {
	sk := kind + "#" + name
	if len(sk) <= maxSortKeyBytes {
		return sk
	}
	return kind + "#sha256:" + digest(name)
}

// activityOp is one activity item's pending counters.
type activityOp struct {
	sk       string
	item     types.DynamoDBActivity
	counters map[string]int
}

// activitySet accumulates counters by sort key, so each activity item is
// written once per batch.
type activitySet map[string]*activityOp

func (s activitySet) add(sk string, item types.DynamoDBActivity, attr string, n int) {
	if n == 0 {
		return
	}
	op, ok := s[sk]
	if !ok {
		op = &activityOp{sk: sk, item: item, counters: map[string]int{}}
		s[sk] = op
	} else {
		op.item.PolicyType = firstNonEmpty(op.item.PolicyType, item.PolicyType)
		op.item.ErrorMessage = firstNonEmpty(op.item.ErrorMessage, item.ErrorMessage)
	}
	op.counters[attr] += n
}

// Event counters are grouped per event source for roles (bounded by that
// service's API) and per event name for services (a busy service's full map
// is larger than the handful of names one file touches).
func bySource(eventKey string) string {
	source, _, _ := strings.Cut(eventKey, ":")
	return source
}

func byName(eventKey string) string { return eventKey }

func (s activitySet) events(group func(string) string, allowed, denied map[string]int) {
	for _, side := range []struct {
		prefix string
		counts map[string]int
	}{{AllowedCounterPrefix, allowed}, {DeniedCounterPrefix, denied}} {
		for key, n := range side.counts {
			if key == "" {
				continue
			}
			g := group(key)
			s.add(ActivitySortKey(ActivityEvent, g), types.DynamoDBActivity{Kind: ActivityEvent, Name: g}, side.prefix+key, n)
		}
	}
}

// services records a role's per-service totals on its per-source event item.
func (s activitySet) services(counts map[string]int) {
	for source, n := range counts {
		if source != "" {
			s.add(ActivitySortKey(ActivityEvent, source), types.DynamoDBActivity{Kind: ActivityEvent, Name: source}, ServiceCountAttr, n)
		}
	}
}

// allowedAccesses keeps one item per resource with a counter per event name.
func (s activitySet) allowedAccesses(accesses []types.ResourceAccessItem) {
	for _, ra := range accesses {
		sk := ActivityResourceAccess + "#" + digest(ra.Service, ra.ResourceAccountID, ra.Resource)
		s.add(sk, types.DynamoDBActivity{
			Kind:              ActivityResourceAccess,
			Service:           ra.Service,
			Resource:          ra.Resource,
			ResourceAccountID: ra.ResourceAccountID,
		}, AllowedCounterPrefix+ra.EventName, ra.Count)
	}
}

// deniedAccesses keeps one item per denied (resource, event, policy): denials
// are rare and each carries its own policy and error message.
func (s activitySet) deniedAccesses(accesses []types.ResourceAccessItem) {
	for _, ra := range accesses {
		sk := ActivityDeniedResourceAccess + "#" + digest(ra.Service, ra.EventName, ra.ResourceAccountID, ra.Resource, ra.PolicyARN)
		s.add(sk, types.DynamoDBActivity{
			Kind:              ActivityDeniedResourceAccess,
			Service:           ra.Service,
			EventName:         ra.EventName,
			Resource:          ra.Resource,
			ResourceAccountID: ra.ResourceAccountID,
			PolicyARN:         ra.PolicyARN,
			PolicyType:        ra.PolicyType,
			ErrorMessage:      ra.ErrorMessage,
		}, CountAttr, ra.Count)
	}
}

func (s activitySet) eventAccesses(accesses []types.EventAccessItem) {
	for _, ea := range accesses {
		sk := ActivityDeniedEventAccess + "#" + digest(ea.Service, ea.EventName, ea.PolicyARN)
		s.add(sk, types.DynamoDBActivity{
			Kind:         ActivityDeniedEventAccess,
			Service:      ea.Service,
			EventName:    ea.EventName,
			PolicyARN:    ea.PolicyARN,
			PolicyType:   ea.PolicyType,
			ErrorMessage: ea.ErrorMessage,
		}, CountAttr, ea.Count)
	}
}

func roleActivity(r *types.DynamoDBRole) activitySet {
	s := activitySet{}
	s.events(bySource, r.TopEventNames, r.TopDeniedEventNames)
	s.services(r.ServicesCount)
	s.allowedAccesses(r.ResourceAccesses)
	s.deniedAccesses(r.DeniedResourceAccesses)
	s.eventAccesses(r.DeniedEventAccesses)
	return s
}

func serviceActivity(svc *types.DynamoDBService) activitySet {
	s := activitySet{}
	s.events(byName, svc.TopEventNames, svc.TopDeniedEventNames)
	return s
}

// legacyCounter names the attribute a migrated legacy count is copied to.
func legacyCounter(attr string) string {
	switch {
	case strings.HasPrefix(attr, AllowedCounterPrefix):
		return LegacyAllowedCounterPrefix + strings.TrimPrefix(attr, AllowedCounterPrefix)
	case strings.HasPrefix(attr, DeniedCounterPrefix):
		return LegacyDeniedCounterPrefix + strings.TrimPrefix(attr, DeniedCounterPrefix)
	case attr == ServiceCountAttr:
		return LegacyServiceCountAttr
	default:
		return LegacyCountAttr
	}
}

// exprBuilder collects placeholder names and values for one expression.
type exprBuilder struct {
	names  map[string]string
	values map[string]ddbtypes.AttributeValue
}

func newExprBuilder() *exprBuilder {
	return &exprBuilder{names: map[string]string{}, values: map[string]ddbtypes.AttributeValue{}}
}

func (b *exprBuilder) name(attr string) string {
	p := "#n" + strconv.Itoa(len(b.names))
	b.names[p] = attr
	return p
}

func (b *exprBuilder) value(v ddbtypes.AttributeValue) string {
	p := ":v" + strconv.Itoa(len(b.values))
	b.values[p] = v
	return p
}

func (b *exprBuilder) setOnce(attr string, v ddbtypes.AttributeValue) string {
	n := b.name(attr)
	return n + " = if_not_exists(" + n + ", " + b.value(v) + ")"
}

func str(v string) ddbtypes.AttributeValue { return &ddbtypes.AttributeValueMemberS{Value: v} }
func num(v int) ddbtypes.AttributeValue {
	return &ddbtypes.AttributeValueMemberN{Value: strconv.Itoa(v)}
}

func joinClauses(set, add, remove []string) string {
	var parts []string
	if len(set) > 0 {
		parts = append(parts, "SET "+strings.Join(set, ", "))
	}
	if len(add) > 0 {
		parts = append(parts, "ADD "+strings.Join(add, ", "))
	}
	if len(remove) > 0 {
		parts = append(parts, "REMOVE "+strings.Join(remove, ", "))
	}
	return strings.Join(parts, " ")
}

// activityUpdate builds one activity item's UpdateItem for some of its
// counters. Descriptive fields are fixed by the sort key, so setting them
// never grows the item. Batch counters are ADDed.
//
// Migrated legacy counts are copied as the maximum of every snapshot copied
// so far: each is set under a condition that the stored copy is absent or no
// larger. Legacy counts only ever grow, so a copy taken from an older snapshot
// fails its condition instead of overwriting a newer one, and a replay of the
// same snapshot rewrites the same values.
func activityUpdate(table, sortAttr, partition string, op *activityOp, attrs []string, migrate bool) *dynamodb.UpdateItemInput {
	b := newExprBuilder()
	var set, add, conditions []string
	assign := func(attr, v string) {
		if v != "" {
			set = append(set, b.name(attr)+" = "+b.value(str(v)))
		}
	}
	it := op.item
	assign("kind", it.Kind)
	assign("name", it.Name)
	assign("service", it.Service)
	assign("event_name", it.EventName)
	assign("resource", it.Resource)
	assign("resource_account_id", it.ResourceAccountID)
	assign("policy_arn", it.PolicyARN)
	for attr, v := range map[string]string{"policy_type": it.PolicyType, "error_message": it.ErrorMessage} {
		if v != "" {
			set = append(set, b.setOnce(attr, str(v)))
		}
	}
	for _, attr := range attrs {
		n := op.counters[attr]
		if migrate {
			name, value := b.name(legacyCounter(attr)), b.value(num(n))
			set = append(set, name+" = "+value)
			conditions = append(conditions, "(attribute_not_exists("+name+") OR "+name+" <= "+value+")")
		} else {
			add = append(add, b.name(attr)+" "+b.value(num(n)))
		}
	}
	var condition *string
	if len(conditions) > 0 {
		condition = aws.String(strings.Join(conditions, " AND "))
	}
	return &dynamodb.UpdateItemInput{
		TableName: aws.String(table),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": str(partition),
			sortAttr:     str(op.sk),
		},
		UpdateExpression:          aws.String(joinClauses(set, add, nil)),
		ConditionExpression:       condition,
		ExpressionAttributeNames:  b.names,
		ExpressionAttributeValues: b.values,
	}
}

// writeActivity applies a set of counters under one noun, splitting large
// counter sets across updates.
func writeActivity(ctx context.Context, store NounStore, table, sortAttr, partition string, set activitySet, migrate bool) error {
	var inputs []*dynamodb.UpdateItemInput
	sks := make([]string, 0, len(set))
	for sk := range set {
		sks = append(sks, sk)
	}
	sort.Strings(sks)
	for _, sk := range sks {
		op := set[sk]
		attrs := make([]string, 0, len(op.counters))
		for attr := range op.counters {
			attrs = append(attrs, attr)
		}
		sort.Strings(attrs)
		per := maxCountersPerUpdate
		if migrate {
			per = maxMigratedCountersPerUpdate // each also adds a condition clause
		}
		for start := 0; start < len(attrs); start += per {
			chunk := attrs[start:min(start+per, len(attrs))]
			inputs = append(inputs, activityUpdate(table, sortAttr, partition, op, chunk, migrate))
		}
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(activityConcurrency)
	errs := make([]error, len(inputs))
	for i, input := range inputs {
		g.Go(func() error {
			if _, err := store.UpdateItem(gctx, input); err != nil {
				errs[i] = fmt.Errorf("activity %s: %w", attrString(input.Key, sortAttr), err)
			}
			return nil
		})
	}
	_ = g.Wait()
	return errors.Join(errs...)
}

// nounUpdate describes one main-item update.
type nounUpdate struct {
	table      string
	sortAttr   string
	customerID string
	id         string
	setOnce    [][2]string // attribute, value; written only if absent
	add        [][2]any    // attribute, int; ADDed
	firstSeen  string
	lastSeen   string
	legacy     []string // inline attributes of the pre-activity layout
}

// nounState is what the writer knows of the stored main item.
type nounState struct {
	exists      bool
	first, last string
	legacy      map[string]ddbtypes.AttributeValue // the item's legacy attributes, if any
}

func (u nounUpdate) key() map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{
		"customerId": str(u.customerID),
		u.sortAttr:   str(u.id),
	}
}

// read fetches the stored bounds and any legacy attributes. Reads are billed
// by item size, not projection, so asking for the legacy attributes costs
// nothing once they are gone.
func (u nounUpdate) read(ctx context.Context, store NounStore, consistent bool) (nounState, error) {
	names := map[string]string{"#k": u.sortAttr, "#f": "first_seen", "#l": "last_seen"}
	projection := []string{"#k", "#f", "#l"}
	for i, attr := range u.legacy {
		p := "#x" + strconv.Itoa(i)
		names[p] = attr
		projection = append(projection, p)
	}
	out, err := store.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:                aws.String(u.table),
		Key:                      u.key(),
		ConsistentRead:           aws.Bool(consistent),
		ProjectionExpression:     aws.String(strings.Join(projection, ", ")),
		ExpressionAttributeNames: names,
	})
	if err != nil {
		return nounState{}, err
	}
	state := nounState{
		exists: len(out.Item) > 0,
		first:  attrString(out.Item, "first_seen"),
		last:   attrString(out.Item, "last_seen"),
	}
	for _, attr := range u.legacy {
		if v, ok := out.Item[attr]; ok {
			if state.legacy == nil {
				state.legacy = map[string]ddbtypes.AttributeValue{}
			}
			state.legacy[attr] = v
		}
	}
	return state, nil
}

// input builds the main-item write for what the writer believes is stored.
//
// Creation sets both bounds under attribute_not_exists on the key, so a read
// that missed an existing item fails the write instead of keeping the stored
// first_seen through if_not_exists. On an existing item each bound is set
// only when it moves, under a condition that rejects a regression.
func (u nounUpdate) input(state nounState) *dynamodb.UpdateItemInput {
	b := newExprBuilder()
	var set, add, conditions []string
	for _, kv := range u.setOnce {
		if kv[1] != "" {
			set = append(set, b.setOnce(kv[0], str(kv[1])))
		}
	}
	bound := func(attr, v, cmp string) {
		n := b.name(attr)
		p := b.value(str(v))
		set = append(set, n+" = "+p)
		if state.exists {
			conditions = append(conditions, "(attribute_not_exists("+n+") OR "+n+" "+cmp+" "+p+")")
		}
	}
	if u.firstSeen != "" && (!state.exists || state.first == "" || u.firstSeen < state.first) {
		bound("first_seen", u.firstSeen, ">")
	}
	if u.lastSeen != "" && (!state.exists || u.lastSeen > state.last) {
		bound("last_seen", u.lastSeen, "<")
	}
	if !state.exists {
		conditions = append(conditions, "attribute_not_exists("+b.name(u.sortAttr)+")")
	}
	for _, kv := range u.add {
		if n := kv[1].(int); n != 0 {
			add = append(add, b.name(kv[0].(string))+" "+b.value(num(n)))
		}
	}
	var condition *string
	if len(conditions) > 0 {
		condition = aws.String(strings.Join(conditions, " AND "))
	}
	return &dynamodb.UpdateItemInput{
		TableName:                 aws.String(u.table),
		Key:                       u.key(),
		UpdateExpression:          aws.String(joinClauses(set, add, nil)),
		ConditionExpression:       condition,
		ExpressionAttributeNames:  b.names,
		ExpressionAttributeValues: b.values,
	}
}

// apply writes the main item once. A failed condition means the read was
// stale or another batch moved a bound; the writer re-reads consistently and
// recomputes. If bounds keep moving past this batch's, its own bounds are no
// longer needed, and the counters are written alone.
func (u nounUpdate) apply(ctx context.Context, store NounStore, state nounState) error {
	for attempt := 1; ; attempt++ {
		_, err := store.UpdateItem(ctx, u.input(state))
		if !isConditionalCheckFailure(err) {
			return err
		}
		if attempt == maxBoundAttempts {
			_, err = store.UpdateItem(ctx, u.input(nounState{exists: true, first: u.firstSeen, last: u.lastSeen}))
			return err
		}
		if state, err = u.read(ctx, store, true); err != nil {
			return err
		}
	}
}

// errLegacyUndecodable marks legacy attributes that cannot be decoded. They
// are left in place: nothing new is added to them, readers still count them,
// and no data is lost.
var errLegacyUndecodable = errors.New("legacy attributes undecodable")

// migrate moves a legacy item's inline counts into activity items:
//
//  1. snapshot: a strongly consistent read of the legacy attributes, so the
//     copy starts from the current history, never an older replica's;
//  2. copy: every count into its activity item, as the maximum over all
//     snapshots copied so far (see activityUpdate);
//  3. remove: delete the legacy attributes only if each still equals the
//     snapshot that was copied.
//
// If the source changed in between (a pre-upgrade writer still merging into
// it, or another batch migrating it), the removal fails and the migration
// restarts from a fresh snapshot; its copies only ever raise the earlier
// ones. A failure at any step leaves the legacy attributes in place, still
// authoritative for readers, and the next write of the noun tries again.
// Nothing is removed until a copy of exactly what is being removed is
// durable.
func (u nounUpdate) migrate(ctx context.Context, store NounStore, decode func(map[string]ddbtypes.AttributeValue) (activitySet, error)) error {
	partition := ActivityPartition(u.customerID, u.id)
	for attempt := 1; ; attempt++ {
		snapshot, err := u.read(ctx, store, true)
		if err != nil {
			return fmt.Errorf("read legacy snapshot: %w", err)
		}
		if len(snapshot.legacy) == 0 {
			return nil // already migrated
		}
		legacy, err := decode(snapshot.legacy)
		if err != nil {
			return fmt.Errorf("%w: %v", errLegacyUndecodable, err)
		}
		if err := writeActivity(ctx, store, u.table, u.sortAttr, partition, legacy, true); err != nil {
			return fmt.Errorf("copy legacy activity: %w", err)
		}

		b := newExprBuilder()
		conditions := []string{"attribute_exists(" + b.name(u.sortAttr) + ")"}
		var remove []string
		for _, attr := range u.legacy {
			n := b.name(attr)
			remove = append(remove, n)
			if v, ok := snapshot.legacy[attr]; ok {
				conditions = append(conditions, n+" = "+b.value(v))
			} else {
				conditions = append(conditions, "attribute_not_exists("+n+")")
			}
		}
		_, err = store.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 aws.String(u.table),
			Key:                       u.key(),
			UpdateExpression:          aws.String(joinClauses(nil, nil, remove)),
			ConditionExpression:       aws.String(strings.Join(conditions, " AND ")),
			ExpressionAttributeNames:  b.names,
			ExpressionAttributeValues: b.values,
		})
		if err == nil {
			log.Printf("LEGACY_MIGRATED: table=%s id=%s activity_items=%d", u.table, u.id, len(legacy))
			return nil
		}
		if !isConditionalCheckFailure(err) {
			return fmt.Errorf("remove legacy attributes: %w", err)
		}
		if attempt == maxMigrationAttempts {
			return fmt.Errorf("legacy attributes changed during %d migration attempts; left in place", attempt)
		}
	}
}

// write runs one noun's batch: migrate any legacy attributes, update the main
// item, then add the batch's activity. A failed migration does not stop the
// batch: its counts go to the main item and batch counters, which are separate
// from the legacy ones, and the migration is retried on the noun's next write.
// The error is still returned for the caller to log.
func (u nounUpdate) write(ctx context.Context, store NounStore, batch activitySet, decode func(map[string]ddbtypes.AttributeValue) (activitySet, error)) error {
	state, err := u.read(ctx, store, false)
	if err != nil {
		return err
	}
	var migrationErr error
	if len(state.legacy) > 0 {
		migrationErr = u.migrate(ctx, store, decode)
		if errors.Is(migrationErr, errLegacyUndecodable) {
			log.Printf("WARNING: %s %s: %v; left in place", u.table, u.id, migrationErr)
			migrationErr = nil
		}
	}
	if err := u.apply(ctx, store, state); err != nil {
		return errors.Join(migrationErr, err)
	}
	err = writeActivity(ctx, store, u.table, u.sortAttr, ActivityPartition(u.customerID, u.id), batch, false)
	return errors.Join(migrationErr, err)
}

// WriteRoleToDynamoDB adds one batch's activity for a role.
func WriteRoleToDynamoDB(ctx context.Context, store NounStore, tableName string, role *types.DynamoDBRole) error {
	u := nounUpdate{
		table:      tableName,
		sortAttr:   RoleSortAttr,
		customerID: role.CustomerID,
		id:         role.ARN,
		setOnce:    [][2]string{{"name", role.Name}, {"account_id", role.AccountID}},
		add:        [][2]any{{"total_events", role.TotalEvents}, {"total_denied_events", role.TotalDeniedEvents}},
		firstSeen:  role.FirstSeen,
		lastSeen:   role.LastSeen,
		legacy:     LegacyRoleAttrs,
	}
	err := u.write(ctx, store, roleActivity(role), func(item map[string]ddbtypes.AttributeValue) (activitySet, error) {
		var legacy types.DynamoDBRole
		if err := attributevalue.UnmarshalMap(item, &legacy); err != nil {
			return nil, err
		}
		return roleActivity(&legacy), nil
	})
	if err != nil {
		return fmt.Errorf("write role %s: %w", role.ARN, err)
	}
	return nil
}

// WriteServiceToDynamoDB adds one batch's activity for a service. Its
// roles_using and resources_used lists are not migrated: the relations table
// holds every service-role and service-resource pair.
func WriteServiceToDynamoDB(ctx context.Context, store NounStore, tableName string, service *types.DynamoDBService) error {
	u := nounUpdate{
		table:      tableName,
		sortAttr:   ServiceSortAttr,
		customerID: service.CustomerID,
		id:         service.EventSource,
		setOnce:    [][2]string{{"display_name", service.DisplayName}, {"category", service.Category}},
		add:        [][2]any{{"total_events", service.TotalEvents}, {"total_denied_events", service.TotalDeniedEvents}},
		firstSeen:  service.FirstSeen,
		lastSeen:   service.LastSeen,
		legacy:     LegacyServiceAttrs,
	}
	err := u.write(ctx, store, serviceActivity(service), func(item map[string]ddbtypes.AttributeValue) (activitySet, error) {
		var legacy types.DynamoDBService
		if err := attributevalue.UnmarshalMap(item, &legacy); err != nil {
			return nil, err
		}
		return serviceActivity(&legacy), nil
	})
	if err != nil {
		return fmt.Errorf("write service %s: %w", service.EventSource, err)
	}
	return nil
}

func attrString(item map[string]ddbtypes.AttributeValue, name string) string {
	if v, ok := item[name].(*ddbtypes.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}
