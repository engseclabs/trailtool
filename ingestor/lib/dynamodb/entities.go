// Write and merge paths for the aggregate nouns: roles, services,
// resources, and accounts (read-merge-write on their natural keys).
package dynamodb

import (
	"context"
	"fmt"
	"log"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

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

// MergeResourceAccessItems merges two ResourceAccessItem slices, combining counts for duplicates
func MergeResourceAccessItems(a, b []types.ResourceAccessItem) []types.ResourceAccessItem {
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

// WriteServiceToDynamoDB merges a per-batch service record into DynamoDB.
func WriteServiceToDynamoDB(ctx context.Context, ddbClient EntityStore, tableName string, service *types.DynamoDBService) error {
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
			service = MergeServiceAggregated(&existing, service)
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

// MergeServiceAggregated merges activity from two batches. Relationship counts
// use max until the relation table supplies exact global distinct counts.
func MergeServiceAggregated(existing, incoming *types.DynamoDBService) *types.DynamoDBService {
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
		TopEventNames:       MergeIntMaps(existing.TopEventNames, incoming.TopEventNames),
		FirstSeen:           earliestNonEmpty(existing.FirstSeen, incoming.FirstSeen),
		LastSeen:            latestNonEmpty(existing.LastSeen, incoming.LastSeen),
		TotalDeniedEvents:   existing.TotalDeniedEvents + incoming.TotalDeniedEvents,
		TopDeniedEventNames: MergeIntMaps(existing.TopDeniedEventNames, incoming.TopDeniedEventNames),
		PeopleCount:         maxInt(existing.PeopleCount, incoming.PeopleCount),
		SessionsCount:       maxInt(existing.SessionsCount, incoming.SessionsCount),
		AccountsCount:       maxInt(existing.AccountsCount, incoming.AccountsCount),
	}
}

// WriteResourceToDynamoDB writes or updates a resource in DynamoDB using read-merge-write pattern
func WriteResourceToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, resource *types.DynamoDBResource) error {
	resource.RolesCount = len(resource.RolesUsing)

	// Query for existing resource
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId":   &ddbtypes.AttributeValueMemberS{Value: resource.CustomerID},
			"resource_key": &ddbtypes.AttributeValueMemberS{Value: resource.ResourceKey},
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
	mergedClickOps := MergeClickOpsAccesses(existing.ClickOpsAccesses, incoming.ClickOpsAccesses)

	// Sum clickops counts, but recount from merged accesses to be accurate
	clickOpsCount := 0
	for _, access := range mergedClickOps {
		clickOpsCount += access.EventCount
	}

	merged := &types.DynamoDBResource{
		CustomerID:          stableNonEmpty(existing.CustomerID, incoming.CustomerID),
		ResourceKey:         stableNonEmpty(existing.ResourceKey, incoming.ResourceKey),
		Identifier:          stableNonEmpty(existing.Identifier, incoming.Identifier),
		Type:                stableResourceType(existing.Type, incoming.Type),
		ARN:                 stableNonEmpty(existing.ARN, incoming.ARN),
		Name:                stableNonEmpty(existing.Name, incoming.Name),
		AccountID:           stableNonEmpty(existing.AccountID, incoming.AccountID),
		TotalEvents:         existing.TotalEvents + incoming.TotalEvents,
		RolesUsing:          mergeSortedUniqueStrings(existing.RolesUsing, incoming.RolesUsing),
		ServicesUsed:        mergeSortedUniqueStrings(existing.ServicesUsed, incoming.ServicesUsed),
		TopEventNames:       MergeIntMaps(existing.TopEventNames, incoming.TopEventNames),
		FirstSeen:           earliestNonEmpty(existing.FirstSeen, incoming.FirstSeen),
		LastSeen:            latestNonEmpty(existing.LastSeen, incoming.LastSeen),
		TotalDeniedEvents:   existing.TotalDeniedEvents + incoming.TotalDeniedEvents,
		TopDeniedEventNames: MergeIntMaps(existing.TopDeniedEventNames, incoming.TopDeniedEventNames),
		PeopleCount:         maxInt(existing.PeopleCount, incoming.PeopleCount),
		SessionsCount:       maxInt(existing.SessionsCount, incoming.SessionsCount),
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
			existing.PersonKey = stableNonEmpty(existing.PersonKey, b[i].PersonKey)
			existing.AccessTime = earliestNonEmpty(existing.AccessTime, b[i].AccessTime)
			existing.AccountID = stableNonEmpty(existing.AccountID, b[i].AccountID)
		} else {
			cp := b[i]
			merged[k] = &cp
		}
	}

	result := make([]types.ClickOpsAccess, 0, len(merged))
	for _, v := range merged {
		result = append(result, *v)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].SessionRef != result[j].SessionRef {
			return result[i].SessionRef < result[j].SessionRef
		}
		return result[i].EventName < result[j].EventName
	})
	return result
}

// WriteAccountToDynamoDB merges a per-batch account record into DynamoDB.
func WriteAccountToDynamoDB(ctx context.Context, ddbClient EntityStore, tableName string, account *types.DynamoDBAccount) error {
	getResult, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": &ddbtypes.AttributeValueMemberS{Value: account.CustomerID},
			"account_id": &ddbtypes.AttributeValueMemberS{Value: account.AccountID},
		},
	})
	if err != nil {
		log.Printf("WARNING: Failed to get existing account: %v", err)
	} else if len(getResult.Item) > 0 {
		var existing types.DynamoDBAccount
		if err := attributevalue.UnmarshalMap(getResult.Item, &existing); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing account: %v", err)
		} else {
			account = MergeAccountAggregated(&existing, account)
		}
	}

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

// MergeAccountAggregated merges activity from two batches. Relationship counts
// use max until the relation table supplies exact global distinct counts.
func MergeAccountAggregated(existing, incoming *types.DynamoDBAccount) *types.DynamoDBAccount {
	return &types.DynamoDBAccount{
		CustomerID:          stableNonEmpty(existing.CustomerID, incoming.CustomerID),
		AccountID:           stableNonEmpty(existing.AccountID, incoming.AccountID),
		AccountName:         stableNonEmpty(existing.AccountName, incoming.AccountName),
		FirstSeen:           earliestNonEmpty(existing.FirstSeen, incoming.FirstSeen),
		LastSeen:            latestNonEmpty(existing.LastSeen, incoming.LastSeen),
		PeopleCount:         maxInt(existing.PeopleCount, incoming.PeopleCount),
		SessionsCount:       maxInt(existing.SessionsCount, incoming.SessionsCount),
		RolesCount:          maxInt(existing.RolesCount, incoming.RolesCount),
		ServicesCount:       maxInt(existing.ServicesCount, incoming.ServicesCount),
		ResourcesCount:      maxInt(existing.ResourcesCount, incoming.ResourcesCount),
		EventsCount:         existing.EventsCount + incoming.EventsCount,
		TopEventNames:       MergeIntMaps(existing.TopEventNames, incoming.TopEventNames),
		TotalDeniedEvents:   existing.TotalDeniedEvents + incoming.TotalDeniedEvents,
		TopDeniedEventNames: MergeIntMaps(existing.TopDeniedEventNames, incoming.TopDeniedEventNames),
		ClickOpsCount:       existing.ClickOpsCount + incoming.ClickOpsCount,
	}
}

func mergeSortedUniqueStrings(a, b []string) []string {
	merged := MergeUniqueStrings(a, b)
	sort.Strings(merged)
	return merged
}

func stableNonEmpty(a, b string) string {
	return earliestNonEmpty(a, b)
}

func stableResourceType(a, b string) string {
	aKnown := a != "" && a != "unknown"
	bKnown := b != "" && b != "unknown"
	if aKnown && bKnown {
		return stableNonEmpty(a, b)
	}
	if aKnown {
		return a
	}
	if bKnown {
		return b
	}
	if a == "unknown" || b == "unknown" {
		return "unknown"
	}
	return ""
}

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
