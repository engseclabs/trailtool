package aggregator

// The role, service, and relation write paths as they were before the
// bounded-item and relation-prefetch changes: read the whole item, merge in
// memory, PutItem it back; and run the create-if-absent path for every edge.
// The write-cost study measures them against the current paths.

import (
	"context"
	"fmt"
	"log"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// legacyWriteRole writes or updates a role in DynamoDB using read-merge-write pattern
func legacyWriteRole(ctx context.Context, ddbClient ddblib.EntityStore, tableName string, role *types.DynamoDBRole) error {
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
			merged := legacyMergeRole(&existingRole, role)

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

// legacyMergeRole merges two DynamoDBRole records, combining their data
func legacyMergeRole(existing *types.DynamoDBRole, new *types.DynamoDBRole) *types.DynamoDBRole {
	// Merge event counts and service/resource counts
	mergedTopEventNames := ddblib.MergeIntMaps(existing.TopEventNames, new.TopEventNames)
	mergedServicesCount := ddblib.MergeIntMaps(existing.ServicesCount, new.ServicesCount)
	mergedResourcesCount := ddblib.MergeIntMaps(existing.ResourcesCount, new.ResourcesCount)
	mergedTopDeniedEventNames := ddblib.MergeIntMaps(existing.TopDeniedEventNames, new.TopDeniedEventNames)

	// Merge resource accesses using similar logic to session merging
	mergedResourceAccesses := legacyMergeResourceAccessItems(existing.ResourceAccesses, new.ResourceAccesses)
	mergedDeniedResourceAccesses := legacyMergeResourceAccessItems(existing.DeniedResourceAccesses, new.DeniedResourceAccesses)
	mergedDeniedEventAccesses := legacyMergeEventAccessItems(existing.DeniedEventAccesses, new.DeniedEventAccesses)

	// Build services_used and resources_used from merged counts
	servicesUsed := make([]string, 0, len(mergedServicesCount))
	for service := range mergedServicesCount {
		servicesUsed = append(servicesUsed, service)
	}
	sort.Strings(servicesUsed)
	resourcesUsed := make([]string, 0, len(mergedResourcesCount))
	for resource := range mergedResourcesCount {
		resourcesUsed = append(resourcesUsed, resource)
	}
	sort.Strings(resourcesUsed)

	merged := &types.DynamoDBRole{
		CustomerID:             stableNonEmpty(existing.CustomerID, new.CustomerID),
		ARN:                    stableNonEmpty(existing.ARN, new.ARN),
		Name:                   stableNonEmpty(existing.Name, new.Name),
		AccountID:              stableNonEmpty(existing.AccountID, new.AccountID),
		FirstSeen:              earliestNonEmpty(existing.FirstSeen, new.FirstSeen),
		LastSeen:               latestNonEmpty(existing.LastSeen, new.LastSeen),
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
		PeopleCount:            maxInt(existing.PeopleCount, new.PeopleCount),
		SessionsCount:          maxInt(existing.SessionsCount, new.SessionsCount),
		AccountsCount:          maxInt(existing.AccountsCount, new.AccountsCount),
	}

	return merged
}

// legacyMergeResourceAccessItems merges two ResourceAccessItem slices, combining counts for duplicates
func legacyMergeResourceAccessItems(a, b []types.ResourceAccessItem) []types.ResourceAccessItem {
	type key struct {
		Service           string
		EventName         string
		ResourceAccountID string
		Resource          string
		PolicyARN         string
	}
	accessMap := make(map[key]*types.ResourceAccessItem)

	// Add all from first slice
	for _, ra := range a {
		k := key{ra.Service, ra.EventName, ra.ResourceAccountID, ra.Resource, ra.PolicyARN}
		cp := ra
		accessMap[k] = &cp
	}

	// Merge from second slice
	for _, ra := range b {
		k := key{ra.Service, ra.EventName, ra.ResourceAccountID, ra.Resource, ra.PolicyARN}
		if existing, exists := accessMap[k]; exists {
			existing.Count += ra.Count
			existing.PolicyType = stableNonEmpty(existing.PolicyType, ra.PolicyType)
			existing.ErrorMessage = stableNonEmpty(existing.ErrorMessage, ra.ErrorMessage)
		} else {
			cp := ra
			accessMap[k] = &cp
		}
	}

	// Convert back to slice
	result := make([]types.ResourceAccessItem, 0, len(accessMap))
	for _, ra := range accessMap {
		result = append(result, *ra)
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i]
		right := result[j]
		if left.Service != right.Service {
			return left.Service < right.Service
		}
		if left.EventName != right.EventName {
			return left.EventName < right.EventName
		}
		if left.ResourceAccountID != right.ResourceAccountID {
			return left.ResourceAccountID < right.ResourceAccountID
		}
		if left.Resource != right.Resource {
			return left.Resource < right.Resource
		}
		return left.PolicyARN < right.PolicyARN
	})

	return result
}

// legacyMergeEventAccessItems merges two EventAccessItem slices, combining counts for duplicates
func legacyMergeEventAccessItems(a, b []types.EventAccessItem) []types.EventAccessItem {
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
	sort.Slice(result, func(i, j int) bool {
		if result[i].Service != result[j].Service {
			return result[i].Service < result[j].Service
		}
		if result[i].EventName != result[j].EventName {
			return result[i].EventName < result[j].EventName
		}
		return result[i].PolicyARN < result[j].PolicyARN
	})

	return result
}

// legacyWriteService merges a per-batch service record into DynamoDB.
func legacyWriteService(ctx context.Context, ddbClient ddblib.EntityStore, tableName string, service *types.DynamoDBService) error {
	service.RolesCount = len(service.RolesUsing)
	service.ResourcesCount = len(service.ResourcesUsed)

	getResult, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId":   &ddbtypes.AttributeValueMemberS{Value: service.CustomerID},
			"event_source": &ddbtypes.AttributeValueMemberS{Value: service.EventSource},
		},
	})
	if err != nil {
		log.Printf("WARNING: Failed to get existing service: %v", err)
	} else if len(getResult.Item) > 0 {
		var existing types.DynamoDBService
		if err := attributevalue.UnmarshalMap(getResult.Item, &existing); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing service: %v", err)
		} else {
			service = legacyMergeService(&existing, service)
		}
	}

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

// legacyMergeService merges activity from two batches. Relationship counts
// use max until the relation table supplies exact global distinct counts.
func legacyMergeService(existing, incoming *types.DynamoDBService) *types.DynamoDBService {
	rolesUsing := mergeSortedUniqueStrings(existing.RolesUsing, incoming.RolesUsing)
	resourcesUsed := mergeSortedUniqueStrings(existing.ResourcesUsed, incoming.ResourcesUsed)

	return &types.DynamoDBService{
		CustomerID:          stableNonEmpty(existing.CustomerID, incoming.CustomerID),
		EventSource:         stableNonEmpty(existing.EventSource, incoming.EventSource),
		DisplayName:         stableNonEmpty(existing.DisplayName, incoming.DisplayName),
		Category:            stableNonEmpty(existing.Category, incoming.Category),
		TotalEvents:         existing.TotalEvents + incoming.TotalEvents,
		RolesUsing:          rolesUsing,
		RolesCount:          len(rolesUsing),
		ResourcesUsed:       resourcesUsed,
		ResourcesCount:      len(resourcesUsed),
		TopEventNames:       ddblib.MergeIntMaps(existing.TopEventNames, incoming.TopEventNames),
		FirstSeen:           earliestNonEmpty(existing.FirstSeen, incoming.FirstSeen),
		LastSeen:            latestNonEmpty(existing.LastSeen, incoming.LastSeen),
		TotalDeniedEvents:   existing.TotalDeniedEvents + incoming.TotalDeniedEvents,
		TopDeniedEventNames: ddblib.MergeIntMaps(existing.TopDeniedEventNames, incoming.TopDeniedEventNames),
		PeopleCount:         maxInt(existing.PeopleCount, incoming.PeopleCount),
		SessionsCount:       maxInt(existing.SessionsCount, incoming.SessionsCount),
		AccountsCount:       maxInt(existing.AccountsCount, incoming.AccountsCount),
	}
}

// legacyWriteRelations writes every edge through the create-if-absent path:
// summary put, create transaction, and on an existing edge a consistent read
// and two boundary updates.
func legacyWriteRelations(ctx context.Context, store ddblib.RelationStore, table string, relations []types.DynamoDBRelation) (ddblib.RelationWriteResult, error) {
	result := ddblib.RelationWriteResult{NewSubjects: map[string]bool{}}
	merged := map[string]types.DynamoDBRelation{}
	for _, r := range relations {
		if r.SubjectID == "" || r.RelatedID == "" {
			continue
		}
		k := r.PK + "\x00" + r.SK
		if prior, ok := merged[k]; ok {
			r.FirstSeen = earliestNonEmpty(prior.FirstSeen, r.FirstSeen)
			r.LastSeen = latestNonEmpty(prior.LastSeen, r.LastSeen)
		}
		merged[k] = r
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		created, err := ddblib.WriteRelation(ctx, store, table, merged[k])
		if err != nil {
			return result, err
		}
		if created {
			result.NewEdges = append(result.NewEdges, merged[k])
		}
	}
	return result, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func mergeSortedUniqueStrings(a, b []string) []string {
	merged := ddblib.MergeUniqueStrings(a, b)
	sort.Strings(merged)
	return merged
}

func stableNonEmpty(a, b string) string { return earliestNonEmpty(a, b) }

func earliestNonEmpty(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" || a < b {
		return a
	}
	return b
}

func latestNonEmpty(a, b string) string {
	if a > b {
		return a
	}
	return b
}
