// Write and merge paths for resources and accounts (read-merge-write on
// their natural keys). Roles and services use the bounded paths in
// activity.go.
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

// WriteResourceToDynamoDB writes or updates a resource in DynamoDB using read-merge-write pattern
func WriteResourceToDynamoDB(ctx context.Context, ddbClient EntityStore, tableName string, resource *types.DynamoDBResource) error {
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
