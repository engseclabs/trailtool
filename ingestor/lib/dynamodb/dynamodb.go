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

// LinkGetter is the subset of the DynamoDB client used by BatchGetIdentityLinks,
// abstracted so the UnprocessedKeys retry loop is unit-testable.
// *dynamodb.Client satisfies it.
type LinkGetter interface {
	BatchGetItem(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
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
