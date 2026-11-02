package store

// Activity items: the per-event, per-service, and resource-access counters the
// ingestor keeps beside each role and service, in that noun's own table under
// the partition "<customerId>#act#<noun id>". The layout is described in
// docs/design/noun-ux-and-data-contracts.md and written by
// ingestor/lib/dynamodb/activity.go; the key helpers below must match it.
//
// Items written by older ingestors keep their counts inline on the main item
// instead. They are not migrated: the ingestor's first write of such an item
// removes the inline maps in the same update that adds the batch, before it
// writes any activity item. So a noun has either inline maps (not written
// since the upgrade) or activity items, never both, and the read path simply
// adds whatever it finds.

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

// ActivityItem is one activity item as stored. Counters are dynamic
// attributes, collected into the maps below.
type ActivityItem struct {
	Kind              string `dynamodbav:"kind"`
	Name              string `dynamodbav:"name"`
	Service           string `dynamodbav:"service"`
	EventName         string `dynamodbav:"event_name"`
	Resource          string `dynamodbav:"resource"`
	ResourceAccountID string `dynamodbav:"resource_account_id"`
	PolicyARN         string `dynamodbav:"policy_arn"`
	PolicyType        string `dynamodbav:"policy_type"`
	ErrorMessage      string `dynamodbav:"error_message"`

	// Counters ("c:", "d:", service_count, count).
	Allowed      map[string]int `dynamodbav:"-"`
	Denied       map[string]int `dynamodbav:"-"`
	ServiceCount int            `dynamodbav:"-"`
	Count        int            `dynamodbav:"-"`
}

func parseActivityItem(raw map[string]types.AttributeValue) (ActivityItem, error) {
	var it ActivityItem
	if err := attributevalue.UnmarshalMap(raw, &it); err != nil {
		return it, err
	}
	for name, v := range raw {
		n, ok := v.(*types.AttributeValueMemberN)
		if !ok {
			continue
		}
		count, err := strconv.Atoi(n.Value)
		if err != nil {
			continue
		}
		prefix, key, _ := strings.Cut(name, ":")
		switch {
		case name == "service_count":
			it.ServiceCount = count
		case name == "count":
			it.Count = count
		case prefix == "c":
			addCount(&it.Allowed, key, count)
		case prefix == "d":
			addCount(&it.Denied, key, count)
		}
	}
	return it, nil
}

// queryActivity reads every activity item of one noun.
func (s *Store) queryActivity(ctx context.Context, table, customerID, nounID string) ([]ActivityItem, error) {
	var items []ActivityItem
	var lastKey map[string]types.AttributeValue
	for {
		out, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(table),
			KeyConditionExpression: aws.String("customerId = :p"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":p": &types.AttributeValueMemberS{Value: ActivityPartition(customerID, nounID)},
			},
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "query activity")
		}
		for _, raw := range out.Items {
			it, err := parseActivityItem(raw)
			if err != nil {
				return nil, fmt.Errorf("unmarshal activity: %w", err)
			}
			items = append(items, it)
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
	items, err := s.queryActivity(ctx, RolesTableName, customerID, role.ARN)
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
	items, err := s.queryActivity(ctx, ServicesTableName, customerID, service.EventSource)
	if err != nil {
		return err
	}
	ApplyServiceActivity(service, items)
	return nil
}

func addCount(dst *map[string]int, key string, n int) {
	if key == "" || n == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[string]int)
	}
	(*dst)[key] += n
}

type resourceAccessKey struct {
	service, eventName, accountID, resource, policyARN string
}

type eventAccessKey struct {
	service, eventName, policyARN string
}

// ApplyRoleActivity adds activity items to whatever inline detail the role
// item carries. Accesses accumulate in maps keyed by their identity and are
// sorted once, so a role with many resources costs O(n log n).
func ApplyRoleActivity(role *models.Role, items []ActivityItem) {
	if len(items) == 0 {
		return
	}
	allowed := make(map[resourceAccessKey]*models.ResourceAccessItem, len(role.ResourceAccesses))
	denied := make(map[resourceAccessKey]*models.ResourceAccessItem, len(role.DeniedResourceAccesses))
	deniedEvents := make(map[eventAccessKey]*models.EventAccessItem, len(role.DeniedEventAccesses))
	addAccess := func(m map[resourceAccessKey]*models.ResourceAccessItem, ra models.ResourceAccessItem) {
		k := resourceAccessKey{ra.Service, ra.EventName, ra.ResourceAccountID, ra.Resource, ra.PolicyARN}
		if cur, ok := m[k]; ok {
			cur.Count += ra.Count
			if cur.PolicyType == "" {
				cur.PolicyType = ra.PolicyType
			}
			if cur.ErrorMessage == "" {
				cur.ErrorMessage = ra.ErrorMessage
			}
			return
		}
		m[k] = &ra
	}
	addEvent := func(ea models.EventAccessItem) {
		k := eventAccessKey{ea.Service, ea.EventName, ea.PolicyARN}
		if cur, ok := deniedEvents[k]; ok {
			cur.Count += ea.Count
			if cur.ErrorMessage == "" {
				cur.ErrorMessage = ea.ErrorMessage
			}
			return
		}
		deniedEvents[k] = &ea
	}
	for _, ra := range role.ResourceAccesses {
		addAccess(allowed, ra)
	}
	for _, ra := range role.DeniedResourceAccesses {
		addAccess(denied, ra)
	}
	for _, ea := range role.DeniedEventAccesses {
		addEvent(ea)
	}

	for _, it := range items {
		a, d, serviceCount, count := it.Allowed, it.Denied, it.ServiceCount, it.Count
		switch it.Kind {
		case activityEvent:
			for k, n := range a {
				addCount(&role.TopEventNames, k, n)
			}
			for k, n := range d {
				addCount(&role.TopDeniedEventNames, k, n)
			}
			addCount(&role.ServicesCount, it.Name, serviceCount)
		case activityResourceAccess:
			// One item per resource, one counter per event name.
			for eventName, n := range a {
				addAccess(allowed, models.ResourceAccessItem{
					Resource: it.Resource, ResourceAccountID: it.ResourceAccountID,
					Service: it.Service, EventName: eventName, Count: n,
				})
			}
		case activityDeniedResourceAccess:
			addAccess(denied, models.ResourceAccessItem{
				Resource: it.Resource, ResourceAccountID: it.ResourceAccountID,
				Service: it.Service, EventName: it.EventName, Count: count,
				PolicyARN: it.PolicyARN, PolicyType: it.PolicyType, ErrorMessage: it.ErrorMessage,
			})
		case activityDeniedEventAccess:
			addEvent(models.EventAccessItem{
				Service: it.Service, EventName: it.EventName, Count: count,
				PolicyARN: it.PolicyARN, PolicyType: it.PolicyType, ErrorMessage: it.ErrorMessage,
			})
		}
	}

	role.ResourceAccesses = sortedAccesses(allowed)
	role.DeniedResourceAccesses = sortedAccesses(denied)
	role.DeniedEventAccesses = make([]models.EventAccessItem, 0, len(deniedEvents))
	for _, ea := range deniedEvents {
		role.DeniedEventAccesses = append(role.DeniedEventAccesses, *ea)
	}
	sort.Slice(role.DeniedEventAccesses, func(i, j int) bool {
		a, b := role.DeniedEventAccesses[i], role.DeniedEventAccesses[j]
		return eventAccessKey{a.Service, a.EventName, a.PolicyARN}.less(eventAccessKey{b.Service, b.EventName, b.PolicyARN})
	})

	// Derived: every allowed resource access was also one count of its
	// resource, and the used-lists are the maps' keys.
	role.ResourcesCount = make(map[string]int)
	for _, ra := range role.ResourceAccesses {
		addCount(&role.ResourcesCount, ra.Resource, ra.Count)
	}
	role.ResourcesUsed = sortedKeys(role.ResourcesCount)
	role.ServicesUsed = sortedKeys(role.ServicesCount)
}

func (k resourceAccessKey) less(o resourceAccessKey) bool {
	for _, p := range [][2]string{{k.service, o.service}, {k.eventName, o.eventName}, {k.accountID, o.accountID}, {k.resource, o.resource}} {
		if p[0] != p[1] {
			return p[0] < p[1]
		}
	}
	return k.policyARN < o.policyARN
}

func (k eventAccessKey) less(o eventAccessKey) bool {
	if k.service != o.service {
		return k.service < o.service
	}
	if k.eventName != o.eventName {
		return k.eventName < o.eventName
	}
	return k.policyARN < o.policyARN
}

func sortedAccesses(m map[resourceAccessKey]*models.ResourceAccessItem) []models.ResourceAccessItem {
	keys := make([]resourceAccessKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].less(keys[j]) })
	out := make([]models.ResourceAccessItem, 0, len(keys))
	for _, k := range keys {
		out = append(out, *m[k])
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ApplyServiceActivity adds per-event activity to a service.
func ApplyServiceActivity(service *models.Service, items []ActivityItem) {
	for _, it := range items {
		if it.Kind != activityEvent {
			continue
		}
		a, d := it.Allowed, it.Denied
		for k, n := range a {
			addCount(&service.TopEventNames, k, n)
		}
		for k, n := range d {
			addCount(&service.TopDeniedEventNames, k, n)
		}
	}
}
