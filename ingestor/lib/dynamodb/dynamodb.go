// Package dynamodb contains DynamoDB write and merge operations for the ingestor.
package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// SessionStore is the subset of the DynamoDB client used by the session write
// paths, abstracted so the windowed extend/fold/conflict logic is unit-testable.
// *dynamodb.Client satisfies it.
type SessionStore interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// WriteRoleToDynamoDB writes or updates a role in DynamoDB using read-merge-write pattern
func WriteRoleToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, role *types.DynamoDBRole) error {
	// Query for existing role with the same customerId and arn
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": &ddbtypes.AttributeValueMemberS{Value: role.CustomerID},
			"arn":        &ddbtypes.AttributeValueMemberS{Value: role.ARN},
		},
	}

	getResult, err := ddbClient.GetItem(ctx, getInput)
	if err != nil {
		log.Printf("WARNING: Failed to get existing role: %v", err)
		// Continue with normal write if get fails
	} else if getResult.Item != nil && len(getResult.Item) > 0 {
		// Role exists - merge it
		var existingRole types.DynamoDBRole
		if err := attributevalue.UnmarshalMap(getResult.Item, &existingRole); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing role: %v", err)
		} else {
			log.Printf("ROLE_MERGE: arn=%s existing_events=%d new_events=%d", role.ARN, existingRole.TotalEvents, role.TotalEvents)

			// Merge the roles
			merged := MergeRoleAggregated(&existingRole, role)

			// Write the merged role
			item, err := attributevalue.MarshalMap(merged)
			if err != nil {
				return fmt.Errorf("failed to marshal merged role: %w", err)
			}

			_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(tableName),
				Item:      item,
			})

			if err != nil {
				return fmt.Errorf("failed to write merged role: %w", err)
			}

			log.Printf("ROLE_MERGED: arn=%s total_events=%d (was %d, +%d) resource_accesses=%d denied_resource_accesses=%d",
				merged.ARN, merged.TotalEvents, existingRole.TotalEvents, role.TotalEvents,
				len(merged.ResourceAccesses), len(merged.DeniedResourceAccesses))

			return nil
		}
	}

	// No existing role - write as new
	log.Printf("ROLE_CREATE: arn=%s events=%d", role.ARN, role.TotalEvents)

	item, err := attributevalue.MarshalMap(role)
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// MergeRoleAggregated merges two DynamoDBRole records, combining their data
func MergeRoleAggregated(existing *types.DynamoDBRole, new *types.DynamoDBRole) *types.DynamoDBRole {
	// Use earlier first_seen and later last_seen
	firstSeen := existing.FirstSeen
	if new.FirstSeen < firstSeen {
		firstSeen = new.FirstSeen
	}
	lastSeen := existing.LastSeen
	if new.LastSeen > lastSeen {
		lastSeen = new.LastSeen
	}

	// Merge event counts and service/resource counts
	mergedTopEventNames := MergeIntMaps(existing.TopEventNames, new.TopEventNames)
	mergedServicesCount := MergeIntMaps(existing.ServicesCount, new.ServicesCount)
	mergedResourcesCount := MergeIntMaps(existing.ResourcesCount, new.ResourcesCount)
	mergedTopDeniedEventNames := MergeIntMaps(existing.TopDeniedEventNames, new.TopDeniedEventNames)

	// Merge resource accesses using similar logic to session merging
	mergedResourceAccesses := MergeResourceAccessItems(existing.ResourceAccesses, new.ResourceAccesses)
	mergedDeniedResourceAccesses := MergeResourceAccessItems(existing.DeniedResourceAccesses, new.DeniedResourceAccesses)
	mergedDeniedEventAccesses := MergeEventAccessItems(existing.DeniedEventAccesses, new.DeniedEventAccesses)

	// Build services_used and resources_used from merged counts
	servicesUsed := make([]string, 0, len(mergedServicesCount))
	for service := range mergedServicesCount {
		servicesUsed = append(servicesUsed, service)
	}
	resourcesUsed := make([]string, 0, len(mergedResourcesCount))
	for resource := range mergedResourcesCount {
		resourcesUsed = append(resourcesUsed, resource)
	}

	merged := &types.DynamoDBRole{
		CustomerID:             new.CustomerID,
		ARN:                    new.ARN,
		Name:                   new.Name,
		AccountID:              new.AccountID,
		FirstSeen:              firstSeen,
		LastSeen:               lastSeen,
		TotalEvents:            existing.TotalEvents + new.TotalEvents,
		ServicesCount:          mergedServicesCount,
		ResourcesCount:         mergedResourcesCount,
		TopEventNames:          mergedTopEventNames,
		ServicesUsed:           servicesUsed,
		ResourcesUsed:          resourcesUsed,
		ResourceAccesses:       mergedResourceAccesses,
		TotalDeniedEvents:      existing.TotalDeniedEvents + new.TotalDeniedEvents,
		TopDeniedEventNames:    mergedTopDeniedEventNames,
		DeniedResourceAccesses: mergedDeniedResourceAccesses,
		DeniedEventAccesses:    mergedDeniedEventAccesses,
		PeopleCount:            existing.PeopleCount + new.PeopleCount,
		SessionsCount:          existing.SessionsCount + new.SessionsCount,
		AccountsCount:          existing.AccountsCount + new.AccountsCount,
	}

	return merged
}

// MergeResourceAccessItems merges two ResourceAccessItem slices, combining counts for duplicates
func MergeResourceAccessItems(a, b []types.ResourceAccessItem) []types.ResourceAccessItem {
	// Use map to aggregate by unique combination of Resource+Service+EventName
	accessMap := make(map[string]*types.ResourceAccessItem)

	// Add all from first slice
	for _, ra := range a {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		accessMap[key] = &types.ResourceAccessItem{
			Resource:     ra.Resource,
			Service:      ra.Service,
			EventName:    ra.EventName,
			Count:        ra.Count,
			PolicyARN:    ra.PolicyARN,
			PolicyType:   ra.PolicyType,
			ErrorMessage: ra.ErrorMessage,
		}
	}

	// Merge from second slice
	for _, ra := range b {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ra.Count
			// Keep the first policy info we saw (could enhance to track multiple policies)
			if existing.PolicyARN == "" && ra.PolicyARN != "" {
				existing.PolicyARN = ra.PolicyARN
				existing.PolicyType = ra.PolicyType
				existing.ErrorMessage = ra.ErrorMessage
			}
		} else {
			accessMap[key] = &types.ResourceAccessItem{
				Resource:     ra.Resource,
				Service:      ra.Service,
				EventName:    ra.EventName,
				Count:        ra.Count,
				PolicyARN:    ra.PolicyARN,
				PolicyType:   ra.PolicyType,
				ErrorMessage: ra.ErrorMessage,
			}
		}
	}

	// Convert back to slice
	result := make([]types.ResourceAccessItem, 0, len(accessMap))
	for _, ra := range accessMap {
		result = append(result, *ra)
	}

	return result
}

// MergeEventAccessItems merges two EventAccessItem slices, combining counts for duplicates
func MergeEventAccessItems(a, b []types.EventAccessItem) []types.EventAccessItem {
	// Use map to aggregate by unique combination of Service+EventName+PolicyARN
	accessMap := make(map[string]*types.EventAccessItem)

	// Add all from first slice
	for _, ea := range a {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		accessMap[key] = &types.EventAccessItem{
			Service:      ea.Service,
			EventName:    ea.EventName,
			Count:        ea.Count,
			PolicyARN:    ea.PolicyARN,
			PolicyType:   ea.PolicyType,
			ErrorMessage: ea.ErrorMessage,
		}
	}

	// Merge from second slice
	for _, ea := range b {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ea.Count
			// Keep the first error message we saw (could enhance to track multiple messages)
			if existing.ErrorMessage == "" && ea.ErrorMessage != "" {
				existing.ErrorMessage = ea.ErrorMessage
			}
		} else {
			accessMap[key] = &types.EventAccessItem{
				Service:      ea.Service,
				EventName:    ea.EventName,
				Count:        ea.Count,
				PolicyARN:    ea.PolicyARN,
				PolicyType:   ea.PolicyType,
				ErrorMessage: ea.ErrorMessage,
			}
		}
	}

	// Convert back to slice
	result := make([]types.EventAccessItem, 0, len(accessMap))
	for _, ea := range accessMap {
		result = append(result, *ea)
	}

	return result
}

// WriteServiceToDynamoDB writes or updates a service in DynamoDB
func WriteServiceToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, service *types.DynamoDBService) error {
	service.RolesCount = len(service.RolesUsing)
	service.ResourcesCount = len(service.ResourcesUsed)

	item, err := attributevalue.MarshalMap(service)
	if err != nil {
		return fmt.Errorf("failed to marshal service: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// WriteResourceToDynamoDB writes or updates a resource in DynamoDB using read-merge-write pattern
func WriteResourceToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, resource *types.DynamoDBResource) error {
	resource.RolesCount = len(resource.RolesUsing)

	// Query for existing resource
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": &ddbtypes.AttributeValueMemberS{Value: resource.CustomerID},
			"identifier": &ddbtypes.AttributeValueMemberS{Value: resource.Identifier},
		},
	}

	getResult, err := ddbClient.GetItem(ctx, getInput)
	if err != nil {
		log.Printf("WARNING: Failed to get existing resource: %v", err)
	} else if getResult.Item != nil && len(getResult.Item) > 0 {
		var existingResource types.DynamoDBResource
		if err := attributevalue.UnmarshalMap(getResult.Item, &existingResource); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing resource: %v", err)
		} else {
			merged := MergeResourceAggregated(&existingResource, resource)
			item, err := attributevalue.MarshalMap(merged)
			if err != nil {
				return fmt.Errorf("failed to marshal merged resource: %w", err)
			}
			_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(tableName),
				Item:      item,
			})
			return err
		}
	}

	// No existing resource - write as new
	item, err := attributevalue.MarshalMap(resource)
	if err != nil {
		return fmt.Errorf("failed to marshal resource: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// MergeResourceAggregated merges two DynamoDBResource records, combining their data
func MergeResourceAggregated(existing *types.DynamoDBResource, incoming *types.DynamoDBResource) *types.DynamoDBResource {
	firstSeen := existing.FirstSeen
	if incoming.FirstSeen < firstSeen {
		firstSeen = incoming.FirstSeen
	}
	lastSeen := existing.LastSeen
	if incoming.LastSeen > lastSeen {
		lastSeen = incoming.LastSeen
	}

	// Use non-empty ARN
	arn := existing.ARN
	if arn == "" {
		arn = incoming.ARN
	}

	// Use non-unknown type
	resourceType := existing.Type
	if resourceType == "unknown" && incoming.Type != "unknown" {
		resourceType = incoming.Type
	}

	mergedClickOps := MergeClickOpsAccesses(existing.ClickOpsAccesses, incoming.ClickOpsAccesses)

	// Sum clickops counts, but recount from merged accesses to be accurate
	clickOpsCount := 0
	for _, access := range mergedClickOps {
		clickOpsCount += access.EventCount
	}

	merged := &types.DynamoDBResource{
		CustomerID:          incoming.CustomerID,
		Identifier:          incoming.Identifier,
		Type:                resourceType,
		ARN:                 arn,
		Name:                incoming.Name,
		AccountID:           incoming.AccountID,
		TotalEvents:         existing.TotalEvents + incoming.TotalEvents,
		RolesUsing:          MergeUniqueStrings(existing.RolesUsing, incoming.RolesUsing),
		ServicesUsed:        MergeUniqueStrings(existing.ServicesUsed, incoming.ServicesUsed),
		TopEventNames:       MergeIntMaps(existing.TopEventNames, incoming.TopEventNames),
		FirstSeen:           firstSeen,
		LastSeen:            lastSeen,
		TotalDeniedEvents:   existing.TotalDeniedEvents + incoming.TotalDeniedEvents,
		TopDeniedEventNames: MergeIntMaps(existing.TopDeniedEventNames, incoming.TopDeniedEventNames),
		PeopleCount:         existing.PeopleCount + incoming.PeopleCount,
		SessionsCount:       existing.SessionsCount + incoming.SessionsCount,
		ClickOpsAccesses:    mergedClickOps,
		ClickOpsCount:       clickOpsCount,
	}
	merged.RolesCount = len(merged.RolesUsing)

	return merged
}

// MergeClickOpsAccesses merges two slices of ClickOpsAccess, deduplicating by session+event
func MergeClickOpsAccesses(a, b []types.ClickOpsAccess) []types.ClickOpsAccess {
	type key struct {
		SessionRef string
		EventName  string
	}
	merged := make(map[key]*types.ClickOpsAccess)

	for i := range a {
		k := key{a[i].SessionRef, a[i].EventName}
		cp := a[i]
		merged[k] = &cp
	}
	for i := range b {
		k := key{b[i].SessionRef, b[i].EventName}
		if existing, ok := merged[k]; ok {
			existing.EventCount += b[i].EventCount
		} else {
			cp := b[i]
			merged[k] = &cp
		}
	}

	result := make([]types.ClickOpsAccess, 0, len(merged))
	for _, v := range merged {
		result = append(result, *v)
	}
	return result
}

// WritePersonToDynamoDB writes or updates a person in DynamoDB using a
// read-merge-write on (customerId, person_key).
func WritePersonToDynamoDB(ctx context.Context, ddbClient SessionStore, tableName string, person *types.DynamoDBPerson) error {
	getResult, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": &ddbtypes.AttributeValueMemberS{Value: person.CustomerID},
			"person_key": &ddbtypes.AttributeValueMemberS{Value: person.PersonKey},
		},
	})
	if err != nil {
		log.Printf("WARNING: Failed to get existing person: %v", err)
	} else if len(getResult.Item) > 0 {
		var existing types.DynamoDBPerson
		if err := attributevalue.UnmarshalMap(getResult.Item, &existing); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing person: %v", err)
		} else {
			person = MergePerson(&existing, person)
		}
	}

	item, err := attributevalue.MarshalMap(person)
	if err != nil {
		return fmt.Errorf("failed to marshal person: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// MergePerson merges an incoming per-batch person record into the stored one.
// EventsCount accumulates; the per-batch unique counts (sessions, roles, …) keep
// the larger of the two values — an approximation until they're recomputed from
// the aggregate tables.
func MergePerson(existing, incoming *types.DynamoDBPerson) *types.DynamoDBPerson {
	merged := *incoming
	if existing.FirstSeen != "" && (merged.FirstSeen == "" || existing.FirstSeen < merged.FirstSeen) {
		merged.FirstSeen = existing.FirstSeen
	}
	if existing.LastSeen > merged.LastSeen {
		merged.LastSeen = existing.LastSeen
	}
	merged.Email = firstNonEmpty(existing.Email, incoming.Email)
	merged.DisplayName = firstNonEmpty(existing.DisplayName, incoming.DisplayName)
	merged.EmailsSeen = MergeUniqueStrings(existing.EmailsSeen, incoming.EmailsSeen)
	merged.EventsCount = existing.EventsCount + incoming.EventsCount
	merged.SessionsCount = maxInt(existing.SessionsCount, incoming.SessionsCount)
	merged.AccountsCount = maxInt(existing.AccountsCount, incoming.AccountsCount)
	merged.RolesCount = maxInt(existing.RolesCount, incoming.RolesCount)
	merged.ServicesCount = maxInt(existing.ServicesCount, incoming.ServicesCount)
	merged.ResourcesCount = maxInt(existing.ResourcesCount, incoming.ResourcesCount)
	return &merged
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// WriteSession writes or updates an anchored session in DynamoDB. The key is
// deterministic (pk = customerId#person_key, sk = anchor#roleID), so cross-batch
// writes for the same credential hit the same item and merge additively via
// read-merge-write. Optimistic locking is not load-bearing here — a concurrent
// double-merge has the same (accepted) exposure as a redelivered partial batch.
func WriteSession(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession) error {
	getResult, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"pk": &ddbtypes.AttributeValueMemberS{Value: session.PK},
			"sk": &ddbtypes.AttributeValueMemberS{Value: session.SK},
		},
	})
	if err != nil {
		log.Printf("WARNING: Failed to get existing session: %v", err)
		// Continue with normal write if the read fails
	} else if len(getResult.Item) > 0 {
		var existing types.DynamoDBSession
		if err := attributevalue.UnmarshalMap(getResult.Item, &existing); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing session: %v", err)
		} else {
			merged := MergeSession(&existing, session)
			merged.Version = existing.Version + 1
			item, err := attributevalue.MarshalMap(merged)
			if err != nil {
				return fmt.Errorf("failed to marshal merged session: %w", err)
			}
			if _, err := ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(tableName),
				Item:      item,
			}); err != nil {
				return fmt.Errorf("failed to write merged session: %w", err)
			}
			log.Printf("SESSION_MERGED: sk=%s events=%d (was %d, +%d)",
				merged.SK, merged.EventsCount, existing.EventsCount, session.EventsCount)
			return nil
		}
	}

	log.Printf("SESSION_CREATE: sk=%s type=%s events=%d start=%s",
		session.SK, session.SessionType, session.EventsCount, session.StartTime)
	item, err := attributevalue.MarshalMap(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}
	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})
	return err
}

// windowDeletion names a win# record folded into another and slated for a
// version-conditional delete.
type windowDeletion struct {
	SK      string
	Version int64
}

// FoldWindows merges an incoming windowed run into the overlapping/adjacent
// existing win# sessions (same channel only). Pure function — the write path
// wraps it in optimistic-lock retries. Returns the surviving record (earliest
// SK, sticky, per §3.2), the version the write must be conditional on (0 =
// fresh create), and the records folded away.
func FoldWindows(existing []types.DynamoDBSession, incoming *types.DynamoDBSession, idleGap time.Duration) (*types.DynamoDBSession, int64, []windowDeletion) {
	var overlapping []types.DynamoDBSession
	for _, e := range existing {
		if e.SessionType == incoming.SessionType &&
			windowsMergeable(e.StartTime, e.EndTime, incoming.StartTime, incoming.EndTime, idleGap) {
			overlapping = append(overlapping, e)
		}
	}
	if len(overlapping) == 0 {
		out := *incoming
		out.Version = 1
		return &out, 0, nil
	}

	sort.Slice(overlapping, func(a, b int) bool { return overlapping[a].SK < overlapping[b].SK })
	target := overlapping[0]
	expectedVersion := target.Version
	merged := MergeSession(&target, incoming)
	var deletions []windowDeletion
	for i := 1; i < len(overlapping); i++ {
		merged = MergeSession(merged, &overlapping[i])
		deletions = append(deletions, windowDeletion{SK: overlapping[i].SK, Version: overlapping[i].Version})
	}
	merged.Version = expectedVersion + 1
	return merged, expectedVersion, deletions
}

// windowsMergeable reports whether two windowed runs belong to one session: the
// gap between them (if any) is at most idleGap.
func windowsMergeable(aStart, aEnd, bStart, bEnd string, idleGap time.Duration) bool {
	as, err1 := time.Parse(time.RFC3339, aStart)
	ae, err2 := time.Parse(time.RFC3339, aEnd)
	bs, err3 := time.Parse(time.RFC3339, bStart)
	be, err4 := time.Parse(time.RFC3339, bEnd)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return false
	}
	return !bs.After(ae.Add(idleGap)) && !as.After(be.Add(idleGap))
}

// WriteWindowedSession merges a windowed (win#) session into DynamoDB — the only
// write path where time guesses and optimistic locking are load-bearing (§3.2):
// fetch potentially-adjacent windows in one Query (±2×idleGap), extend/fold
// overlapping runs, write back conditionally on version, retry ≤3 on conflict.
// A fold that deletes records runs as one transaction so a concurrent writer can
// never observe (or double-merge) a partially applied fold.
func WriteWindowedSession(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession, idleGap time.Duration) error {
	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		existing, err := queryAdjacentWindows(ctx, ddbClient, tableName, session, idleGap)
		if err != nil {
			return fmt.Errorf("query adjacent windows: %w", err)
		}
		merged, expectedVersion, deletions := FoldWindows(existing, session, idleGap)

		if len(deletions) == 0 {
			err = putWindowConditional(ctx, ddbClient, tableName, merged, expectedVersion)
		} else {
			err = transactFoldWindows(ctx, ddbClient, tableName, merged, expectedVersion, deletions)
		}
		if err == nil {
			return nil
		}
		if !isVersionConflict(err) {
			return err
		}
		lastErr = err // concurrent writer got there first — re-read and converge
	}
	return fmt.Errorf("windowed session write did not converge after %d retries: %w", maxRetries, lastErr)
}

// transactFoldWindows applies a fold atomically: the merged survivor is written
// and the folded-away records deleted in one transaction, each guarded by the
// version read during the fold.
func transactFoldWindows(ctx context.Context, ddbClient SessionStore, tableName string, merged *types.DynamoDBSession, expectedVersion int64, deletions []windowDeletion) error {
	item, err := attributevalue.MarshalMap(merged)
	if err != nil {
		return fmt.Errorf("failed to marshal windowed session: %w", err)
	}
	put := &ddbtypes.Put{
		TableName: aws.String(tableName),
		Item:      item,
	}
	if expectedVersion == 0 {
		put.ConditionExpression = aws.String("attribute_not_exists(pk)")
	} else {
		put.ConditionExpression = aws.String("version = :expected")
		put.ExpressionAttributeValues = map[string]ddbtypes.AttributeValue{
			":expected": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", expectedVersion)},
		}
	}
	items := []ddbtypes.TransactWriteItem{{Put: put}}
	for _, d := range deletions {
		items = append(items, ddbtypes.TransactWriteItem{Delete: &ddbtypes.Delete{
			TableName: aws.String(tableName),
			Key: map[string]ddbtypes.AttributeValue{
				"pk": &ddbtypes.AttributeValueMemberS{Value: merged.PK},
				"sk": &ddbtypes.AttributeValueMemberS{Value: d.SK},
			},
			ConditionExpression: aws.String("version = :expected"),
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":expected": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", d.Version)},
			},
		}})
	}
	_, err = ddbClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	return err
}

// queryAdjacentWindows fetches win# sessions for the same person and roleID
// whose sticky start keys fall within ±2×idleGap of the incoming run.
func queryAdjacentWindows(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession, idleGap time.Duration) ([]types.DynamoDBSession, error) {
	start, err := time.Parse(time.RFC3339, session.StartTime)
	if err != nil {
		return nil, fmt.Errorf("unparsable session start %q: %w", session.StartTime, err)
	}
	end, err := time.Parse(time.RFC3339, session.EndTime)
	if err != nil {
		end = start
	}
	prefix := "win#" + session.RoleID + "#"
	lo := prefix + start.Add(-2*idleGap).UTC().Format(time.RFC3339)
	hi := prefix + end.Add(2*idleGap).UTC().Format(time.RFC3339)

	out, err := ddbClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(tableName),
		KeyConditionExpression: aws.String("pk = :pk AND sk BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":pk": &ddbtypes.AttributeValueMemberS{Value: session.PK},
			":lo": &ddbtypes.AttributeValueMemberS{Value: lo},
			":hi": &ddbtypes.AttributeValueMemberS{Value: hi},
		},
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]types.DynamoDBSession, 0, len(out.Items))
	for _, item := range out.Items {
		var s types.DynamoDBSession
		if err := attributevalue.UnmarshalMap(item, &s); err != nil {
			log.Printf("WARNING: failed to unmarshal windowed session: %v", err)
			continue
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

func putWindowConditional(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession, expectedVersion int64) error {
	item, err := attributevalue.MarshalMap(session)
	if err != nil {
		return fmt.Errorf("failed to marshal windowed session: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	}
	if expectedVersion == 0 {
		input.ConditionExpression = aws.String("attribute_not_exists(pk)")
	} else {
		input.ConditionExpression = aws.String("version = :expected")
		input.ExpressionAttributeValues = map[string]ddbtypes.AttributeValue{
			":expected": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", expectedVersion)},
		}
	}
	_, err = ddbClient.PutItem(ctx, input)
	return err
}

// isVersionConflict reports whether a write lost an optimistic-lock race: a
// plain conditional-check failure, or a transaction cancelled by one.
func isVersionConflict(err error) bool {
	var ccf *ddbtypes.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return true
	}
	var tc *ddbtypes.TransactionCanceledException
	if errors.As(err, &tc) {
		for _, reason := range tc.CancellationReasons {
			if reason.Code != nil && *reason.Code == "ConditionalCheckFailed" {
				return true
			}
		}
	}
	return false
}

// MergeSession merges two session records for the same key, combining their
// data. The existing record's identity fields and sort key win (the SK is
// sticky for win# sessions); Version is the caller's concern.
func MergeSession(existing *types.DynamoDBSession, incoming *types.DynamoDBSession) *types.DynamoDBSession {
	// RFC3339 UTC timestamps compare lexicographically.
	startTime := existing.StartTime
	if incoming.StartTime != "" && (startTime == "" || incoming.StartTime < startTime) {
		startTime = incoming.StartTime
	}
	endTime := existing.EndTime
	if incoming.EndTime > endTime {
		endTime = incoming.EndTime
	}
	durationMinutes := 0
	if start, err := time.Parse(time.RFC3339, startTime); err == nil {
		if end, err := time.Parse(time.RFC3339, endTime); err == nil {
			durationMinutes = int(end.Sub(start).Minutes())
		}
	}

	mergedEventCounts := MergeIntMaps(existing.EventCounts, incoming.EventCounts)
	mergedResourcesAccessed := MergeIntMaps(existing.ResourcesAccessed, incoming.ResourcesAccessed)

	// Session type specificity: "agent" (MCP OAuth traffic) is the most specific,
	// then "login" (aws login). Prefer the more specific type if either side
	// carries it; otherwise keep the existing type.
	sessionType := existing.SessionType
	if incoming.SessionType == "login" || existing.SessionType == "login" {
		sessionType = "login"
	}
	if incoming.SessionType == "agent" || existing.SessionType == "agent" {
		sessionType = "agent"
	}

	return &types.DynamoDBSession{
		PK:          existing.PK,
		SK:          existing.SK, // sticky
		CustomerID:  existing.CustomerID,
		PersonKey:   existing.PersonKey,
		Anchor:      firstNonEmpty(existing.Anchor, incoming.Anchor),
		SessionType: sessionType,
		RoleARN:     firstNonEmpty(existing.RoleARN, incoming.RoleARN),
		RoleID:      firstNonEmpty(existing.RoleID, incoming.RoleID),
		RoleName:    firstNonEmpty(existing.RoleName, incoming.RoleName),
		AccountID:   firstNonEmpty(existing.AccountID, incoming.AccountID),
		RoleKey:     firstNonEmpty(existing.RoleKey, incoming.RoleKey),
		AccountKey:  firstNonEmpty(existing.AccountKey, incoming.AccountKey),

		StartTime:       startTime,
		EndTime:         endTime,
		DurationMinutes: durationMinutes,
		Version:         existing.Version,

		EventsCount:             existing.EventsCount + incoming.EventsCount,
		ServiceDrivenEventCount: existing.ServiceDrivenEventCount + incoming.ServiceDrivenEventCount,
		SourceIPs:               MergeUniqueStrings(existing.SourceIPs, incoming.SourceIPs),
		UserAgents:              MergeUniqueStrings(existing.UserAgents, incoming.UserAgents),
		EventCounts:             mergedEventCounts,
		ResourcesAccessed:       mergedResourcesAccessed,
		ResourceAccesses:        MergeResourceAccesses(existing.ResourceAccesses, incoming.ResourceAccesses),
		ServicesCount:           CountUniqueServices(mergedEventCounts),
		ResourcesCount:          len(mergedResourcesAccessed),

		DeniedEventCount:        existing.DeniedEventCount + incoming.DeniedEventCount,
		DeniedEventCounts:       MergeIntMaps(existing.DeniedEventCounts, incoming.DeniedEventCounts),
		DeniedResourcesAccessed: MergeIntMaps(existing.DeniedResourcesAccessed, incoming.DeniedResourcesAccessed),
		DeniedResourceAccesses:  MergeResourceAccesses(existing.DeniedResourceAccesses, incoming.DeniedResourceAccesses),
		DeniedEventAccesses:     MergeEventAccesses(existing.DeniedEventAccesses, incoming.DeniedEventAccesses),

		ClickOpsEventCount:  existing.ClickOpsEventCount + incoming.ClickOpsEventCount,
		ClickOpsEventCounts: MergeIntMaps(existing.ClickOpsEventCounts, incoming.ClickOpsEventCounts),

		SignInSessionArn: firstNonEmpty(existing.SignInSessionArn, incoming.SignInSessionArn),

		AssumedFromSession: firstNonEmpty(existing.AssumedFromSession, incoming.AssumedFromSession),
		AssumedFromRoleARN: firstNonEmpty(existing.AssumedFromRoleARN, incoming.AssumedFromRoleARN),
		ChainedSessionRefs: MergeUniqueStrings(existing.ChainedSessionRefs, incoming.ChainedSessionRefs),
		ChainedRoles:       MergeUniqueStrings(existing.ChainedRoles, incoming.ChainedRoles),
		ChainedEventCount:  existing.ChainedEventCount + incoming.ChainedEventCount,

		SessionTags:   mergeSessionTags(existing.SessionTags, incoming.SessionTags),
		SessionPolicy: firstNonEmpty(existing.SessionPolicy, incoming.SessionPolicy),

		LoginGrantedBySession:    firstNonEmpty(existing.LoginGrantedBySession, incoming.LoginGrantedBySession),
		MCPResource:              firstNonEmpty(existing.MCPResource, incoming.MCPResource),
		AgentAuthorizedBySession: firstNonEmpty(existing.AgentAuthorizedBySession, incoming.AgentAuthorizedBySession),
	}
}

// mergeSessionTags returns the non-nil session tags map, preferring existing over new.
// If both are non-nil, existing wins (the first write has the authoritative tags).
func mergeSessionTags(existing, new map[string]string) map[string]string {
	if existing != nil {
		return existing
	}
	return new
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// MergeUniqueStrings merges two string slices, removing duplicates
func MergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// MergeIntMaps merges two map[string]int by adding counts
func MergeIntMaps(a, b map[string]int) map[string]int {
	result := make(map[string]int)

	for k, v := range a {
		result[k] = v
	}

	for k, v := range b {
		result[k] += v
	}

	return result
}

// CountUniqueServices counts unique services from event counts map
// Event counts are stored as "eventSource:eventName" -> count
func CountUniqueServices(eventCounts map[string]int) int {
	services := make(map[string]bool)
	for eventKey := range eventCounts {
		// Extract eventSource from "eventSource:eventName"
		parts := strings.Split(eventKey, ":")
		if len(parts) >= 1 {
			services[parts[0]] = true
		}
	}
	return len(services)
}

// MergeResourceAccesses merges two ResourceAccess slices, combining counts for duplicates
func MergeResourceAccesses(a, b []types.ResourceAccess) []types.ResourceAccess {
	// Use map to aggregate by unique combination of Resource+Service+EventName
	accessMap := make(map[string]*types.ResourceAccess)

	// Add all from first slice
	for _, ra := range a {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		accessMap[key] = &types.ResourceAccess{
			Resource:  ra.Resource,
			Service:   ra.Service,
			EventName: ra.EventName,
			Count:     ra.Count,
		}
	}

	// Merge from second slice
	for _, ra := range b {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ra.Count
		} else {
			accessMap[key] = &types.ResourceAccess{
				Resource:  ra.Resource,
				Service:   ra.Service,
				EventName: ra.EventName,
				Count:     ra.Count,
			}
		}
	}

	// Convert back to slice
	result := make([]types.ResourceAccess, 0, len(accessMap))
	for _, ra := range accessMap {
		result = append(result, *ra)
	}

	return result
}

// MergeEventAccesses merges two EventAccess slices, combining counts for duplicates
func MergeEventAccesses(a, b []types.EventAccess) []types.EventAccess {
	// Use map to aggregate by unique combination of Service+EventName+PolicyARN
	accessMap := make(map[string]*types.EventAccess)

	// Add all from first slice
	for _, ea := range a {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		accessMap[key] = &types.EventAccess{
			Service:      ea.Service,
			EventName:    ea.EventName,
			Count:        ea.Count,
			PolicyARN:    ea.PolicyARN,
			PolicyType:   ea.PolicyType,
			ErrorMessage: ea.ErrorMessage,
		}
	}

	// Merge from second slice
	for _, ea := range b {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ea.Count
			// Keep the first error message we saw (could enhance to track multiple messages)
			if existing.ErrorMessage == "" && ea.ErrorMessage != "" {
				existing.ErrorMessage = ea.ErrorMessage
			}
		} else {
			accessMap[key] = &types.EventAccess{
				Service:      ea.Service,
				EventName:    ea.EventName,
				Count:        ea.Count,
				PolicyARN:    ea.PolicyARN,
				PolicyType:   ea.PolicyType,
				ErrorMessage: ea.ErrorMessage,
			}
		}
	}

	// Convert back to slice
	result := make([]types.EventAccess, 0, len(accessMap))
	for _, ea := range accessMap {
		result = append(result, *ea)
	}

	return result
}

// WriteIdentityLink writes an identity link record (cred#/chain#/login#/mcp#)
// to trailtool-identity-links. TTL is the caller's concern (12h — the STS max
// credential lifetime).
func WriteIdentityLink(ctx context.Context, ddbClient SessionStore, tableName string, link *types.DynamoDBIdentityLink) error {
	item, err := attributevalue.MarshalMap(link)
	if err != nil {
		return fmt.Errorf("failed to marshal identity link: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("failed to write identity link: %w", err)
	}

	log.Printf("IDENTITY_LINK_WRITE: pk=%s person=%s parent=%s", link.PK, link.PersonKey, link.ParentSessionRef)
	return nil
}

// BatchGetIdentityLinks fetches identity link records for a set of PKs.
// Returns a map of pk -> DynamoDBIdentityLink for found records.
func BatchGetIdentityLinks(ctx context.Context, ddbClient *dynamodb.Client, tableName string, pks []string) (map[string]*types.DynamoDBIdentityLink, error) {
	result := make(map[string]*types.DynamoDBIdentityLink)
	if len(pks) == 0 {
		return result, nil
	}

	// DynamoDB BatchGetItem limit is 100 keys per request
	const batchSize = 100
	for i := 0; i < len(pks); i += batchSize {
		end := i + batchSize
		if end > len(pks) {
			end = len(pks)
		}
		batch := pks[i:end]

		keys := make([]map[string]ddbtypes.AttributeValue, 0, len(batch))
		for _, pk := range batch {
			keys = append(keys, map[string]ddbtypes.AttributeValue{
				"pk": &ddbtypes.AttributeValueMemberS{Value: pk},
			})
		}

		out, err := ddbClient.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
			RequestItems: map[string]ddbtypes.KeysAndAttributes{
				tableName: {Keys: keys},
			},
		})
		if err != nil {
			return result, fmt.Errorf("batch get identity links failed: %w", err)
		}

		for _, item := range out.Responses[tableName] {
			var link types.DynamoDBIdentityLink
			if err := attributevalue.UnmarshalMap(item, &link); err != nil {
				log.Printf("WARNING: failed to unmarshal identity link: %v", err)
				continue
			}
			result[link.PK] = &link
		}
	}

	return result, nil
}

// UpdateParentSessionChaining updates an existing parent session in DynamoDB with
// chaining metadata from a child (assumed role) session. Used when the parent was
// ingested in a prior Lambda invocation and is not in the current in-memory map.
//
// Session refs are "person_key|sk"; the table key is (customerId#person_key, sk).
func UpdateParentSessionChaining(ctx context.Context, ddbClient SessionStore, tableName, customerID, parentRef, childRef, childRoleARN string, childEventCount int) error {
	personKey, sk, ok := strings.Cut(parentRef, "|")
	if !ok || personKey == "" || sk == "" {
		return fmt.Errorf("invalid parent session ref: %s", parentRef)
	}
	pk := customerID + "#" + personKey

	getOut, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"pk": &ddbtypes.AttributeValueMemberS{Value: pk},
			"sk": &ddbtypes.AttributeValueMemberS{Value: sk},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to get parent session %s: %w", parentRef, err)
	}
	if len(getOut.Item) == 0 {
		// Parent not yet in DDB — will be attributed by a later batch's merge.
		log.Printf("CHAIN_PARENT_UPDATE: parent session not yet in DDB, skipping update for %s", parentRef)
		return nil
	}

	var existing types.DynamoDBSession
	if err := attributevalue.UnmarshalMap(getOut.Item, &existing); err != nil {
		return fmt.Errorf("failed to unmarshal parent session %s: %w", parentRef, err)
	}

	// Apply chaining updates (deduplicated).
	existing.ChainedEventCount += childEventCount
	existing.ChainedRoles = MergeUniqueStrings(existing.ChainedRoles, []string{childRoleARN})
	existing.ChainedSessionRefs = MergeUniqueStrings(existing.ChainedSessionRefs, []string{childRef})
	existing.Version++

	item, err := attributevalue.MarshalMap(&existing)
	if err != nil {
		return fmt.Errorf("failed to marshal updated parent session %s: %w", parentRef, err)
	}
	if _, err := ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	}); err != nil {
		return fmt.Errorf("failed to write updated parent session %s: %w", parentRef, err)
	}

	log.Printf("CHAIN_PARENT_UPDATE: updated parent=%s with child=%s role=%s", parentRef, childRef, childRoleARN)
	return nil
}

// MarkFileIngested records an S3 object as processed in trailtool-ingested-files
// (TTL 30 days) — the redelivery idempotency marker.
func MarkFileIngested(ctx context.Context, ddbClient SessionStore, tableName, objectKey string, now time.Time) error {
	rec := &types.DynamoDBIngestedFile{
		ObjectKey:  objectKey,
		IngestedAt: now.UTC().Format(time.RFC3339),
		TTL:        now.Add(30 * 24 * time.Hour).Unix(),
	}
	item, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal ingested-file marker: %w", err)
	}
	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})
	return err
}

// IsFileIngested reports whether an S3 object already has an ingestion marker.
func IsFileIngested(ctx context.Context, ddbClient SessionStore, tableName, objectKey string) (bool, error) {
	out, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"object_key": &ddbtypes.AttributeValueMemberS{Value: objectKey},
		},
	})
	if err != nil {
		return false, err
	}
	return len(out.Item) > 0, nil
}

// WriteAccountToDynamoDB writes or updates an account in DynamoDB
func WriteAccountToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, account *types.DynamoDBAccount) error {
	item, err := attributevalue.MarshalMap(account)
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}
