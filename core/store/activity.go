package store

// Activity items: the per-event, per-service, per-resource-access, and
// ClickOps counters the ingestor keeps beside each role, service, resource,
// and account, in that noun's own table under the partition
// "<customerId>#act#<noun id>". The layout is described in
// docs/design/noun-ux-and-data-contracts.md and written by
// ingestor/lib/dynamodb/activity.go; the key helpers below must match it.
//
// Items written by older ingestors keep these counters inline on the main
// item instead. The ingestor moves them into activity items the next time it
// writes the noun, removing them from the main item in the same update, so a
// count is in exactly one place at any time and the read path sums both.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/core/models"
)

const (
	activityPartitionInfix = "#act#"
	maxActivityPartition   = 1536

	activityEvent                = "evt"
	activityResourceAccess       = "ra"
	activityDeniedResourceAccess = "dra"
	activityDeniedEventAccess    = "dea"
	activityClickOps             = "co"
)

// ActivityPartition is the partition key value of a noun's activity items.
func ActivityPartition(customerID, nounID string) string {
	p := customerID + activityPartitionInfix + nounID
	if len(p) <= maxActivityPartition {
		return p
	}
	sum := sha256.Sum256([]byte(nounID))
	return customerID + activityPartitionInfix + "sha256:" + hex.EncodeToString(sum[:16])
}

// Counter attributes: per-event counters are top-level number attributes
// named by prefix and event key.
const (
	allowedCounterPrefix = "c:"
	deniedCounterPrefix  = "d:"
	serviceCountAttr     = "service_count"
)

// ActivityItem is one activity item as stored.
type ActivityItem struct {
	Kind              string `dynamodbav:"kind"`
	Name              string `dynamodbav:"name"`
	Count             int    `dynamodbav:"count"`
	Service           string `dynamodbav:"service"`
	EventName         string `dynamodbav:"event_name"`
	Resource          string `dynamodbav:"resource"`
	ResourceAccountID string `dynamodbav:"resource_account_id"`
	PolicyARN         string `dynamodbav:"policy_arn"`
	PolicyType        string `dynamodbav:"policy_type"`
	ErrorMessage      string `dynamodbav:"error_message"`
	SessionRef        string `dynamodbav:"session_ref"`
	PersonKey         string `dynamodbav:"person_key"`
	AccessTime        string `dynamodbav:"access_time"`

	// Allowed and Denied are the item's "c:" and "d:" counters by event key;
	// ServiceCount is a role's per-service total.
	Allowed      map[string]int `dynamodbav:"-"`
	Denied       map[string]int `dynamodbav:"-"`
	ServiceCount int            `dynamodbav:"-"`
}

// counterAttributes reads the dynamic counter attributes of one item.
func counterAttributes(item map[string]types.AttributeValue) (allowed, denied map[string]int, serviceCount int) {
	for name, v := range item {
		n, ok := v.(*types.AttributeValueMemberN)
		if !ok {
			continue
		}
		count, err := strconv.Atoi(n.Value)
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(name, allowedCounterPrefix):
			addCounts(&allowed, strings.TrimPrefix(name, allowedCounterPrefix), count)
		case strings.HasPrefix(name, deniedCounterPrefix):
			addCounts(&denied, strings.TrimPrefix(name, deniedCounterPrefix), count)
		case name == serviceCountAttr:
			serviceCount = count
		}
	}
	return allowed, denied, serviceCount
}

// addInlineEventCounters adds a resource main item's own event counters.
func addInlineEventCounters(resource *models.Resource, item map[string]types.AttributeValue) {
	allowed, denied, _ := counterAttributes(item)
	for k, n := range allowed {
		addCounts(&resource.TopEventNames, k, n)
	}
	for k, n := range denied {
		addCounts(&resource.TopDeniedEventNames, k, n)
	}
}

// queryActivity reads every activity item of one noun, optionally only those
// whose sort key starts with kind+"#".
func (s *Store) queryActivity(ctx context.Context, table, sortAttr, customerID, nounID, kind string) ([]ActivityItem, error) {
	keyCond := "customerId = :p"
	values := map[string]types.AttributeValue{
		":p": &types.AttributeValueMemberS{Value: ActivityPartition(customerID, nounID)},
	}
	var names map[string]string
	if kind != "" {
		keyCond += " AND begins_with(#sk, :kind)"
		names = map[string]string{"#sk": sortAttr}
		values[":kind"] = &types.AttributeValueMemberS{Value: kind + "#"}
	}
	var items []ActivityItem
	var lastKey map[string]types.AttributeValue
	for {
		out, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(table),
			KeyConditionExpression:    aws.String(keyCond),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
			ExclusiveStartKey:         lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "query activity")
		}
		for _, raw := range out.Items {
			var item ActivityItem
			if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
				return nil, fmt.Errorf("unmarshal activity: %w", err)
			}
			item.Allowed, item.Denied, item.ServiceCount = counterAttributes(raw)
			items = append(items, item)
		}
		if out.LastEvaluatedKey == nil {
			return items, nil
		}
		lastKey = out.LastEvaluatedKey
	}
}

// LoadRoleActivity fills a role's per-event, per-service, and resource-access
// detail from its activity items.
func (s *Store) LoadRoleActivity(ctx context.Context, customerID string, role *models.Role) error {
	if role == nil {
		return nil
	}
	items, err := s.queryActivity(ctx, RolesTableName, "arn", customerID, role.ARN, "")
	if err != nil {
		return err
	}
	ApplyRoleActivity(role, items)
	return nil
}

// LoadServiceActivity fills a service's per-event counts.
func (s *Store) LoadServiceActivity(ctx context.Context, customerID string, service *models.Service) error {
	if service == nil {
		return nil
	}
	items, err := s.queryActivity(ctx, ServicesTableName, "event_source", customerID, service.EventSource, "")
	if err != nil {
		return err
	}
	ApplyServiceActivity(service, items)
	return nil
}

// LoadAccountActivity fills an account's per-event counts.
func (s *Store) LoadAccountActivity(ctx context.Context, customerID string, account *models.Account) error {
	if account == nil {
		return nil
	}
	items, err := s.queryActivity(ctx, AccountsTableName, "account_id", customerID, account.AccountID, "")
	if err != nil {
		return err
	}
	ApplyAccountActivity(account, items)
	return nil
}

// LoadResourceActivity fills a resource's ClickOps accesses.
func (s *Store) LoadResourceActivity(ctx context.Context, customerID string, resource *models.Resource) error {
	if resource == nil {
		return nil
	}
	return s.loadResourceClickOps(ctx, customerID, resource)
}

// loadResourceClickOps reads only a resource's ClickOps items, for the
// ClickOps list, which needs nothing else.
func (s *Store) loadResourceClickOps(ctx context.Context, customerID string, resource *models.Resource) error {
	items, err := s.queryActivity(ctx, ResourcesTableName, "resource_key", customerID, resource.ResourceKey, activityClickOps)
	if err != nil {
		return err
	}
	ApplyResourceActivity(resource, items)
	return nil
}

func addEventCounters(allowed, denied *map[string]int, it ActivityItem) {
	for k, n := range it.Allowed {
		addCounts(allowed, k, n)
	}
	for k, n := range it.Denied {
		addCounts(denied, k, n)
	}
}

func addCounts(dst *map[string]int, key string, n int) {
	if key == "" || n == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[string]int)
	}
	(*dst)[key] += n
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ApplyRoleActivity adds activity items to whatever legacy detail the role
// item still carries.
func ApplyRoleActivity(role *models.Role, items []ActivityItem) {
	for _, it := range items {
		switch it.Kind {
		case activityEvent:
			addEventCounters(&role.TopEventNames, &role.TopDeniedEventNames, it)
			addCounts(&role.ServicesCount, it.Name, it.ServiceCount)
		case activityResourceAccess:
			// One item per resource, one counter per event name.
			for eventName, n := range it.Allowed {
				access := it
				access.EventName = eventName
				access.Count = n
				role.ResourceAccesses = mergeResourceAccess(role.ResourceAccesses, access)
			}
		case activityDeniedResourceAccess:
			role.DeniedResourceAccesses = mergeResourceAccess(role.DeniedResourceAccesses, it)
		case activityDeniedEventAccess:
			role.DeniedEventAccesses = mergeEventAccess(role.DeniedEventAccesses, it)
		}
	}
	// Resource counts and the used-lists are derived: every allowed resource
	// access was also one count of its resource.
	if len(items) > 0 {
		role.ResourcesCount = map[string]int{}
		for _, ra := range role.ResourceAccesses {
			addCounts(&role.ResourcesCount, ra.Resource, ra.Count)
		}
		role.ResourcesUsed = sortedKeys(role.ResourcesCount)
		role.ServicesUsed = sortedKeys(role.ServicesCount)
	}
	sortResourceAccesses(role.ResourceAccesses)
	sortResourceAccesses(role.DeniedResourceAccesses)
	sort.Slice(role.DeniedEventAccesses, func(i, j int) bool {
		a, b := role.DeniedEventAccesses[i], role.DeniedEventAccesses[j]
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.EventName != b.EventName {
			return a.EventName < b.EventName
		}
		return a.PolicyARN < b.PolicyARN
	})
}

func mergeResourceAccess(list []models.ResourceAccessItem, it ActivityItem) []models.ResourceAccessItem {
	for i := range list {
		ra := &list[i]
		if ra.Service == it.Service && ra.EventName == it.EventName && ra.ResourceAccountID == it.ResourceAccountID &&
			ra.Resource == it.Resource && ra.PolicyARN == it.PolicyARN {
			ra.Count += it.Count
			if ra.PolicyType == "" {
				ra.PolicyType = it.PolicyType
			}
			if ra.ErrorMessage == "" {
				ra.ErrorMessage = it.ErrorMessage
			}
			return list
		}
	}
	return append(list, models.ResourceAccessItem{
		Resource:          it.Resource,
		ResourceAccountID: it.ResourceAccountID,
		Service:           it.Service,
		EventName:         it.EventName,
		Count:             it.Count,
		PolicyARN:         it.PolicyARN,
		PolicyType:        it.PolicyType,
		ErrorMessage:      it.ErrorMessage,
	})
}

func mergeEventAccess(list []models.EventAccessItem, it ActivityItem) []models.EventAccessItem {
	for i := range list {
		ea := &list[i]
		if ea.Service == it.Service && ea.EventName == it.EventName && ea.PolicyARN == it.PolicyARN {
			ea.Count += it.Count
			if ea.ErrorMessage == "" {
				ea.ErrorMessage = it.ErrorMessage
			}
			return list
		}
	}
	return append(list, models.EventAccessItem{
		Service:      it.Service,
		EventName:    it.EventName,
		Count:        it.Count,
		PolicyARN:    it.PolicyARN,
		PolicyType:   it.PolicyType,
		ErrorMessage: it.ErrorMessage,
	})
}

func sortResourceAccesses(list []models.ResourceAccessItem) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		for _, pair := range [][2]string{
			{a.Service, b.Service}, {a.EventName, b.EventName},
			{a.ResourceAccountID, b.ResourceAccountID}, {a.Resource, b.Resource},
		} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return a.PolicyARN < b.PolicyARN
	})
}

// ApplyServiceActivity adds per-event activity to a service.
func ApplyServiceActivity(service *models.Service, items []ActivityItem) {
	for _, it := range items {
		if it.Kind == activityEvent {
			addEventCounters(&service.TopEventNames, &service.TopDeniedEventNames, it)
		}
	}
}

// ApplyAccountActivity adds per-event activity to an account.
func ApplyAccountActivity(account *models.Account, items []ActivityItem) {
	for _, it := range items {
		if it.Kind == activityEvent {
			addEventCounters(&account.TopEventNames, &account.TopDeniedEventNames, it)
		}
	}
}

// ApplyResourceActivity adds ClickOps accesses to a resource. A resource's
// event counters are on its main item (see addInlineEventCounters).
func ApplyResourceActivity(resource *models.Resource, items []ActivityItem) {
	for _, it := range items {
		switch it.Kind {
		case activityClickOps:
			merged := false
			for i := range resource.ClickOpsAccesses {
				c := &resource.ClickOpsAccesses[i]
				if c.SessionRef == it.SessionRef && c.EventName == it.EventName {
					c.EventCount += it.Count
					merged = true
					break
				}
			}
			if !merged {
				resource.ClickOpsAccesses = append(resource.ClickOpsAccesses, models.ClickOpsAccess{
					SessionRef: it.SessionRef,
					PersonKey:  it.PersonKey,
					EventName:  it.EventName,
					AccessTime: it.AccessTime,
					EventCount: it.Count,
					AccountID:  it.ResourceAccountID,
				})
			}
		}
	}
}
