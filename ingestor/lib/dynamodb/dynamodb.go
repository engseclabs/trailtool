// Package dynamodb contains DynamoDB write and merge operations for the ingestor.
package dynamodb

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
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

// EntityStore is the subset of DynamoDB used by aggregate noun writes.
// *dynamodb.Client satisfies it.
type EntityStore interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// RelationStore is the DynamoDB surface used by relation writes.
type RelationStore interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(ctx context.Context, params *dynamodb.TransactWriteItemsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// LinkGetter is the subset of the DynamoDB client used by BatchGetIdentityLinks,
// abstracted so the UnprocessedKeys retry loop is unit-testable.
// *dynamodb.Client satisfies it.
type LinkGetter interface {
	BatchGetItem(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
}

// LinkUpdater is the DynamoDB surface used by creation# correlation records.
// UpdateItem lets metadata and target refs arrive independently without either
// side replacing the fields written by the other.
type LinkUpdater interface {
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// SessionTagStore is the DynamoDB surface used by late creation-metadata
// updates. The read supplies the optimistic-lock version; UpdateItem changes
// only session_tags and version, preserving concurrently written activity.
type SessionTagStore interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// mergeSessionTags combines observed session tags, preserving an existing value
// when the same key appears again. This lets late session-creation metadata add
// keys without replacing the first observed value.
func mergeSessionTags(existing, new map[string]string) map[string]string {
	if len(existing) == 0 && len(new) == 0 {
		return nil
	}
	merged := make(map[string]string, len(existing)+len(new))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range new {
		if _, found := merged[key]; !found {
			merged[key] = value
		}
	}
	return merged
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
