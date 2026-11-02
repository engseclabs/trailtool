// Bounded write paths for the aggregate nouns: roles, services, resources,
// and accounts.
//
// Each noun's main item holds only fixed-size fields: identity, first/last
// seen, and running totals (plus, for a resource, its per-event counters,
// which its service's API bounds). Everything that grows with activity
// (per-event counts, per-service counts, resource accesses, ClickOps
// accesses) lives in small activity items next to it, grouped so that one
// file touches few of them (see types.DynamoDBActivity). Both are
// written with UpdateItem: counters with ADD, identity with if_not_exists, and
// last_seen only when it moves forward. No path reads an item and writes it
// back, so a write costs what the small item weighs, not what the noun has
// accumulated, and no item can reach DynamoDB's 400 KB limit.
//
// Items written before this layout carry the old unbounded attributes. The
// first update of such an item REMOVEs them and, from the returned old image,
// replays their counts into activity items, so the item shrinks once and the
// history is kept. DynamoDB returns the old image to exactly one writer, so a
// legacy item is migrated once even under concurrent batches.
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

// NounStore is the DynamoDB surface the noun write paths use.
// *dynamodb.Client satisfies it.
type NounStore interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

const (
	// ActivityPartitionInfix joins a customer ID and a noun ID into the
	// partition that holds the noun's activity items. Namespaces never
	// contain '#', so these partitions never collide with a customer's own.
	ActivityPartitionInfix = "#act#"

	ActivityEvent                = "evt"
	ActivityResourceAccess       = "ra"
	ActivityDeniedResourceAccess = "dra"
	ActivityDeniedEventAccess    = "dea"
	ActivityClickOps             = "co"

	// maxPartitionKeyBytes keeps activity partitions under DynamoDB's
	// 2048-byte partition key limit; longer noun IDs are hashed.
	maxPartitionKeyBytes = 1536
	// maxSortKeyBytes keeps activity sort keys under the 1024-byte limit.
	maxSortKeyBytes = 768

	// activityConcurrency bounds in-flight activity updates per noun.
	activityConcurrency = 8

	// maxCountersPerUpdate keeps an update expression well under DynamoDB's
	// 4 KB expression limit; larger increments are split across updates.
	maxCountersPerUpdate = 100
)

// Sort-key attribute of each aggregate table.
const (
	RoleSortAttr     = "arn"
	ServiceSortAttr  = "event_source"
	ResourceSortAttr = "resource_key"
	AccountSortAttr  = "account_id"
)

// Attributes older ingestors wrote on the main item. Each is now either kept
// in activity items or derivable from them or from the relations table.
var (
	legacyRoleAttrs = []string{
		"services_used", "services_count", "resources_used", "resources_count",
		"top_event_names", "top_denied_event_names",
		"resource_accesses", "denied_resource_accesses", "denied_event_accesses",
	}
	legacyServiceAttrs  = []string{"roles_using", "resources_used", "top_event_names", "top_denied_event_names"}
	legacyResourceAttrs = []string{"roles_using", "services_used", "top_event_names", "top_denied_event_names", "clickops_accesses"}
	legacyAccountAttrs  = []string{"top_event_names", "top_denied_event_names"}
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

// ActivitySortKey is the sort key of one named activity item (evt#).
func ActivitySortKey(kind, name string) string {
	sk := kind + "#" + name
	if len(sk) <= maxSortKeyBytes {
		return sk
	}
	return kind + "#sha256:" + digest(name)
}

// Counter attribute names. An activity item holds one counter per event as a
// top-level number attribute, so ADD can create and increment it in one
// write, without the map path DynamoDB requires to exist first.
const (
	AllowedCounterPrefix = "c:"
	DeniedCounterPrefix  = "d:"
	ServiceCountAttr     = "service_count"
	CountAttr            = "count"
)

// activityOp is one activity item's pending increments.
type activityOp struct {
	sk       string
	item     types.DynamoDBActivity
	counters map[string]int
}

// split divides an op's counters into ops of at most n counters each.
func (op *activityOp) split(n int) []*activityOp {
	if len(op.counters) <= n {
		return []*activityOp{op}
	}
	attrs := make([]string, 0, len(op.counters))
	for attr := range op.counters {
		attrs = append(attrs, attr)
	}
	sort.Strings(attrs)
	var out []*activityOp
	for start := 0; start < len(attrs); start += n {
		part := &activityOp{sk: op.sk, item: op.item, counters: map[string]int{}}
		for _, attr := range attrs[start:min(start+n, len(attrs))] {
			part.counters[attr] = op.counters[attr]
		}
		out = append(out, part)
	}
	return out
}

// activitySet accumulates increments by sort key, so each activity item is
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
		op.item.AccessTime = earliestNonEmpty(op.item.AccessTime, item.AccessTime)
		op.item.PersonKey = firstNonEmpty(op.item.PersonKey, item.PersonKey)
	}
	op.counters[attr] += n
}

// Event counters are grouped into items by a per-noun rule that keeps each
// item small while a batch touches few of them:
//
//   - roles and accounts: one item per event source ("evt#s3.amazonaws.com"),
//     bounded by that service's API;
//   - services: one item per event name, since a busy service's whole map is
//     larger than the handful of names one file touches;
//   - resources: on the main item itself (see resourceCounters), bounded by
//     the API of the resource's service.
func bySource(eventKey string) string {
	source, _, _ := strings.Cut(eventKey, ":")
	return source
}

func byName(eventKey string) string { return eventKey }

func (s activitySet) events(group func(string) string, allowed, denied map[string]int) {
	for prefix, counts := range map[string]map[string]int{AllowedCounterPrefix: allowed, DeniedCounterPrefix: denied} {
		for key, n := range counts {
			if key == "" {
				continue
			}
			g := group(key)
			s.add(ActivitySortKey(ActivityEvent, g), types.DynamoDBActivity{Kind: ActivityEvent, Name: g}, prefix+key, n)
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

// allowedAccesses groups a role's allowed resource accesses into one item per
// resource, with a counter per event name.
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

func (s activitySet) clickOps(accesses []types.ClickOpsAccess) {
	for _, c := range accesses {
		sk := ActivityClickOps + "#" + digest(c.SessionRef, c.EventName)
		s.add(sk, types.DynamoDBActivity{
			Kind:              ActivityClickOps,
			SessionRef:        c.SessionRef,
			EventName:         c.EventName,
			PersonKey:         c.PersonKey,
			AccessTime:        c.AccessTime,
			ResourceAccountID: c.AccountID,
		}, CountAttr, c.EventCount)
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

func resourceActivity(r *types.DynamoDBResource) activitySet {
	s := activitySet{}
	s.clickOps(r.ClickOpsAccesses)
	return s
}

// resourceCounters are a resource's event counters, kept on its main item.
func resourceCounters(r *types.DynamoDBResource) [][2]any {
	var out [][2]any
	for prefix, counts := range map[string]map[string]int{AllowedCounterPrefix: r.TopEventNames, DeniedCounterPrefix: r.TopDeniedEventNames} {
		for name, n := range counts {
			if name != "" {
				out = append(out, [2]any{prefix + name, n})
			}
		}
	}
	return out
}

func accountActivity(a *types.DynamoDBAccount) activitySet {
	s := activitySet{}
	s.events(bySource, a.TopEventNames, a.TopDeniedEventNames)
	return s
}

func (s activitySet) merge(other activitySet) {
	for sk, op := range other {
		for attr, n := range op.counters {
			s.add(sk, op.item, attr, n)
		}
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

// activityUpdate builds the UpdateItem for one activity item: descriptive
// fields are set (they are fixed by the sort key, so this never grows the
// item), first-observed context with if_not_exists, and counts with ADD.
func activityUpdate(table, sortAttr, partition string, op *activityOp) *dynamodb.UpdateItemInput {
	b := newExprBuilder()
	var set, add []string
	assign := func(attr, v string) {
		if v != "" {
			set = append(set, b.name(attr)+" = "+b.value(str(v)))
		}
	}
	assignOnce := func(attr, v string) {
		if v != "" {
			n := b.name(attr)
			set = append(set, n+" = if_not_exists("+n+", "+b.value(str(v))+")")
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
	assign("session_ref", it.SessionRef)
	assignOnce("policy_type", it.PolicyType)
	assignOnce("error_message", it.ErrorMessage)
	assignOnce("person_key", it.PersonKey)
	assignOnce("access_time", it.AccessTime)
	attrs := make([]string, 0, len(op.counters))
	for attr := range op.counters {
		attrs = append(attrs, attr)
	}
	sort.Strings(attrs)
	for _, attr := range attrs {
		add = append(add, b.name(attr)+" "+b.value(num(op.counters[attr])))
	}
	return &dynamodb.UpdateItemInput{
		TableName: aws.String(table),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": str(partition),
			sortAttr:     str(op.sk),
		},
		UpdateExpression:          aws.String(joinClauses(set, add, nil)),
		ExpressionAttributeNames:  b.names,
		ExpressionAttributeValues: b.values,
	}
}

// writeActivity applies a set of activity increments under one noun.
func writeActivity(ctx context.Context, store NounStore, table, sortAttr, partition string, set activitySet) error {
	if len(set) == 0 {
		return nil
	}
	sks := make([]string, 0, len(set))
	for sk := range set {
		sks = append(sks, sk)
	}
	sort.Strings(sks)
	var inputs []*dynamodb.UpdateItemInput
	for _, sk := range sks {
		for _, op := range set[sk].split(maxCountersPerUpdate) {
			inputs = append(inputs, activityUpdate(table, sortAttr, partition, op))
		}
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(activityConcurrency)
	errs := make([]error, len(inputs))
	for i, input := range inputs {
		g.Go(func() error {
			if _, err := store.UpdateItem(gctx, input); err != nil {
				errs[i] = fmt.Errorf("activity %s: %w", stringAttr(input.Key, sortAttr), err)
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
	remove     []string
}

func (u nounUpdate) key() map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{
		"customerId": str(u.customerID),
		u.sortAttr:   str(u.id),
	}
}

func (u nounUpdate) input(moveFirst, moveLast bool) *dynamodb.UpdateItemInput {
	b := newExprBuilder()
	var set, add, remove, conditions []string
	for _, kv := range u.setOnce {
		if kv[1] == "" {
			continue
		}
		n := b.name(kv[0])
		set = append(set, n+" = if_not_exists("+n+", "+b.value(str(kv[1]))+")")
	}
	if u.firstSeen != "" {
		n := b.name("first_seen")
		v := b.value(str(u.firstSeen))
		if moveFirst {
			set = append(set, n+" = "+v)
			conditions = append(conditions, n+" > "+v)
		} else {
			set = append(set, n+" = if_not_exists("+n+", "+v+")")
		}
	}
	if moveLast {
		n := b.name("last_seen")
		v := b.value(str(u.lastSeen))
		set = append(set, n+" = "+v)
		conditions = append(conditions, "(attribute_not_exists("+n+") OR "+n+" < "+v+")")
	}
	for _, kv := range u.add {
		if n := kv[1].(int); n != 0 {
			add = append(add, b.name(kv[0].(string))+" "+b.value(num(n)))
		}
	}
	for _, attr := range u.remove {
		remove = append(remove, b.name(attr))
	}
	var condition *string
	if len(conditions) > 0 {
		condition = aws.String(strings.Join(conditions, " AND "))
	}
	return &dynamodb.UpdateItemInput{
		TableName:                 aws.String(u.table),
		Key:                       u.key(),
		UpdateExpression:          aws.String(joinClauses(set, add, remove)),
		ConditionExpression:       condition,
		ExpressionAttributeNames:  b.names,
		ExpressionAttributeValues: b.values,
		ReturnValues:              ddbtypes.ReturnValueAllOld,
	}
}

// storedBounds reads a noun's first_seen and last_seen. An eventually
// consistent read costs half a read unit; a stale answer only makes the
// conditional write below fail and retry with a consistent one.
func (u nounUpdate) storedBounds(ctx context.Context, store NounStore, consistent bool) (first, last string, err error) {
	out, err := store.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:                aws.String(u.table),
		Key:                      u.key(),
		ConsistentRead:           aws.Bool(consistent),
		ProjectionExpression:     aws.String("#f, #l"),
		ExpressionAttributeNames: map[string]string{"#f": "first_seen", "#l": "last_seen"},
	})
	if err != nil {
		return "", "", err
	}
	return stringAttr(out.Item, "first_seen"), stringAttr(out.Item, "last_seen"), nil
}

// apply writes the main item in one UpdateItem and returns its old image (nil
// when new).
//
// first_seen and last_seen only widen. Reading them first lets the write set
// exactly the bounds that move, under conditions that reject a regression if
// another batch moved them in between; a rejected write is retried from a
// consistent read. Without the read, every batch whose files arrived out of
// order would pay for a failed conditional write and a second one.
func (u nounUpdate) apply(ctx context.Context, store NounStore) (map[string]ddbtypes.AttributeValue, error) {
	const maxAttempts = 4
	consistent := false
	for attempt := 0; ; attempt++ {
		first, last, err := u.storedBounds(ctx, store, consistent)
		if err != nil {
			return nil, err
		}
		moveFirst := u.firstSeen != "" && first != "" && u.firstSeen < first
		moveLast := u.lastSeen != "" && u.lastSeen > last
		out, err := store.UpdateItem(ctx, u.input(moveFirst, moveLast))
		if isConditionalCheckFailure(err) && attempt+1 < maxAttempts {
			consistent = true
			continue
		}
		if isConditionalCheckFailure(err) {
			// Bounds keep moving under us; record the counters without them.
			out, err = store.UpdateItem(ctx, u.input(false, false))
		}
		if err != nil {
			return nil, err
		}
		if len(out.Attributes) == 0 {
			return nil, nil
		}
		return out.Attributes, nil
	}
}

func stringAttr(item map[string]ddbtypes.AttributeValue, name string) string {
	if v, ok := item[name].(*ddbtypes.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func hasAnyAttr(item map[string]ddbtypes.AttributeValue, names []string) bool {
	for _, n := range names {
		if _, ok := item[n]; ok {
			return true
		}
	}
	return false
}

// WriteRoleToDynamoDB adds one batch's activity for a role.
func WriteRoleToDynamoDB(ctx context.Context, store NounStore, tableName string, role *types.DynamoDBRole) error {
	old, err := nounUpdate{
		table:      tableName,
		sortAttr:   RoleSortAttr,
		customerID: role.CustomerID,
		id:         role.ARN,
		setOnce:    [][2]string{{"name", role.Name}, {"account_id", role.AccountID}},
		add:        [][2]any{{"total_events", role.TotalEvents}, {"total_denied_events", role.TotalDeniedEvents}},
		firstSeen:  role.FirstSeen,
		lastSeen:   role.LastSeen,
		remove:     legacyRoleAttrs,
	}.apply(ctx, store)
	if err != nil {
		return fmt.Errorf("update role %s: %w", role.ARN, err)
	}
	set := roleActivity(role)
	if hasAnyAttr(old, legacyRoleAttrs) {
		var legacy types.DynamoDBRole
		if err := attributevalue.UnmarshalMap(old, &legacy); err != nil {
			log.Printf("WARNING: role %s: legacy attributes unreadable, not migrated: %v", role.ARN, err)
		} else {
			legacySet := roleActivity(&legacy)
			log.Printf("LEGACY_MIGRATE: role=%s activity_items=%d", role.ARN, len(legacySet))
			set.merge(legacySet)
		}
	}
	if err := writeActivity(ctx, store, tableName, RoleSortAttr, ActivityPartition(role.CustomerID, role.ARN), set); err != nil {
		return fmt.Errorf("role %s activity: %w", role.ARN, err)
	}
	return nil
}

// WriteServiceToDynamoDB adds one batch's activity for a service.
func WriteServiceToDynamoDB(ctx context.Context, store NounStore, tableName string, service *types.DynamoDBService) error {
	old, err := nounUpdate{
		table:      tableName,
		sortAttr:   ServiceSortAttr,
		customerID: service.CustomerID,
		id:         service.EventSource,
		setOnce:    [][2]string{{"display_name", service.DisplayName}, {"category", service.Category}},
		add:        [][2]any{{"total_events", service.TotalEvents}, {"total_denied_events", service.TotalDeniedEvents}},
		firstSeen:  service.FirstSeen,
		lastSeen:   service.LastSeen,
		remove:     legacyServiceAttrs,
	}.apply(ctx, store)
	if err != nil {
		return fmt.Errorf("update service %s: %w", service.EventSource, err)
	}
	set := serviceActivity(service)
	if hasAnyAttr(old, legacyServiceAttrs) {
		var legacy types.DynamoDBService
		if err := attributevalue.UnmarshalMap(old, &legacy); err != nil {
			log.Printf("WARNING: service %s: legacy attributes unreadable, not migrated: %v", service.EventSource, err)
		} else {
			legacySet := serviceActivity(&legacy)
			log.Printf("LEGACY_MIGRATE: service=%s activity_items=%d", service.EventSource, len(legacySet))
			set.merge(legacySet)
		}
	}
	if err := writeActivity(ctx, store, tableName, ServiceSortAttr, ActivityPartition(service.CustomerID, service.EventSource), set); err != nil {
		return fmt.Errorf("service %s activity: %w", service.EventSource, err)
	}
	return nil
}

// WriteResourceToDynamoDB adds one batch's activity for a resource.
func WriteResourceToDynamoDB(ctx context.Context, store NounStore, tableName string, resource *types.DynamoDBResource) error {
	clickOps := 0
	for _, c := range resource.ClickOpsAccesses {
		clickOps += c.EventCount
	}
	counters := resourceCounters(resource)
	var overflow [][2]any
	if len(counters) > maxCountersPerUpdate {
		counters, overflow = counters[:maxCountersPerUpdate], counters[maxCountersPerUpdate:]
	}
	u := nounUpdate{
		table:      tableName,
		sortAttr:   ResourceSortAttr,
		customerID: resource.CustomerID,
		id:         resource.ResourceKey,
		setOnce: [][2]string{
			{"identifier", resource.Identifier},
			{"arn", resource.ARN},
			{"name", resource.Name},
			{"account_id", resource.AccountID},
			{"type", resource.Type},
		},
		add: append([][2]any{
			{"total_events", resource.TotalEvents},
			{"total_denied_events", resource.TotalDeniedEvents},
			{"clickops_count", clickOps},
		}, counters...),
		firstSeen: resource.FirstSeen,
		lastSeen:  resource.LastSeen,
		remove:    legacyResourceAttrs,
	}
	old, err := u.apply(ctx, store)
	if err != nil {
		return fmt.Errorf("update resource %s: %w", resource.ResourceKey, err)
	}
	if err := addCounters(ctx, store, u, overflow); err != nil {
		return fmt.Errorf("update resource %s counters: %w", resource.ResourceKey, err)
	}
	if err := upgradeResourceType(ctx, store, u, stringAttr(old, "type"), resource.Type); err != nil {
		return fmt.Errorf("update resource %s type: %w", resource.ResourceKey, err)
	}
	set := resourceActivity(resource)
	if hasAnyAttr(old, legacyResourceAttrs) {
		var legacy types.DynamoDBResource
		if err := attributevalue.UnmarshalMap(old, &legacy); err != nil {
			log.Printf("WARNING: resource %s: legacy attributes unreadable, not migrated: %v", resource.ResourceKey, err)
		} else {
			legacySet := resourceActivity(&legacy)
			log.Printf("LEGACY_MIGRATE: resource=%s activity_items=%d", resource.ResourceKey, len(legacySet))
			set.merge(legacySet)
			if err := addCounters(ctx, store, u, resourceCounters(&legacy)); err != nil {
				return fmt.Errorf("resource %s legacy counters: %w", resource.ResourceKey, err)
			}
		}
	}
	if err := writeActivity(ctx, store, tableName, ResourceSortAttr, ActivityPartition(resource.CustomerID, resource.ResourceKey), set); err != nil {
		return fmt.Errorf("resource %s activity: %w", resource.ResourceKey, err)
	}
	return nil
}

// addCounters ADDs counters to a main item (used to replay legacy maps).
func addCounters(ctx context.Context, store NounStore, u nounUpdate, counters [][2]any) error {
	if len(counters) == 0 {
		return nil
	}
	for start := 0; start < len(counters); start += maxCountersPerUpdate {
		b := newExprBuilder()
		var add []string
		for _, kv := range counters[start:min(start+maxCountersPerUpdate, len(counters))] {
			if n := kv[1].(int); n != 0 {
				add = append(add, b.name(kv[0].(string))+" "+b.value(num(n)))
			}
		}
		if len(add) == 0 {
			continue
		}
		if _, err := store.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 aws.String(u.table),
			Key:                       u.key(),
			UpdateExpression:          aws.String(joinClauses(nil, add, nil)),
			ExpressionAttributeNames:  b.names,
			ExpressionAttributeValues: b.values,
		}); err != nil {
			return err
		}
	}
	return nil
}

// upgradeResourceType replaces an unknown stored type with a known one, the
// one identity field that may legitimately change after creation.
func upgradeResourceType(ctx context.Context, store NounStore, u nounUpdate, stored, incoming string) error {
	// An absent type was filled by the main update's if_not_exists.
	if incoming == "" || incoming == "unknown" || stored != "unknown" {
		return nil
	}
	_, err := store.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(u.table),
		Key:                       u.key(),
		UpdateExpression:          aws.String("SET #t = :t"),
		ConditionExpression:       aws.String("attribute_not_exists(#t) OR #t = :unknown"),
		ExpressionAttributeNames:  map[string]string{"#t": "type"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":t": str(incoming), ":unknown": str("unknown")},
	})
	if isConditionalCheckFailure(err) {
		return nil
	}
	return err
}

// WriteAccountToDynamoDB adds one batch's activity for an account.
func WriteAccountToDynamoDB(ctx context.Context, store NounStore, tableName string, account *types.DynamoDBAccount) error {
	old, err := nounUpdate{
		table:      tableName,
		sortAttr:   AccountSortAttr,
		customerID: account.CustomerID,
		id:         account.AccountID,
		setOnce:    [][2]string{{"account_name", account.AccountName}},
		add: [][2]any{
			{"events_count", account.EventsCount},
			{"total_denied_events", account.TotalDeniedEvents},
			{"clickops_count", account.ClickOpsCount},
		},
		firstSeen: account.FirstSeen,
		lastSeen:  account.LastSeen,
		remove:    legacyAccountAttrs,
	}.apply(ctx, store)
	if err != nil {
		return fmt.Errorf("update account %s: %w", account.AccountID, err)
	}
	set := accountActivity(account)
	if hasAnyAttr(old, legacyAccountAttrs) {
		var legacy types.DynamoDBAccount
		if err := attributevalue.UnmarshalMap(old, &legacy); err != nil {
			log.Printf("WARNING: account %s: legacy attributes unreadable, not migrated: %v", account.AccountID, err)
		} else {
			legacySet := accountActivity(&legacy)
			log.Printf("LEGACY_MIGRATE: account=%s activity_items=%d", account.AccountID, len(legacySet))
			set.merge(legacySet)
		}
	}
	if err := writeActivity(ctx, store, tableName, AccountSortAttr, ActivityPartition(account.CustomerID, account.AccountID), set); err != nil {
		return fmt.Errorf("account %s activity: %w", account.AccountID, err)
	}
	return nil
}
