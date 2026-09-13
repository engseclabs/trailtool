// Identity links (trailtool-identity-links), parent-session chaining
// updates, and ingested-file markers.
package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

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

// WriteCreationLink atomically merges the two independently delivered sides
// of a creation# record. Metadata owns session_tags, while activity adds one or
// more target_session_refs. Neither update can erase the other.
func WriteCreationLink(ctx context.Context, ddbClient LinkUpdater, tableName string, link *types.DynamoDBIdentityLink) error {
	if link == nil || link.PK == "" {
		return fmt.Errorf("creation link requires a pk")
	}

	names := map[string]string{
		"#ttl": "ttl",
	}
	values := map[string]ddbtypes.AttributeValue{
		":ttl": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", link.TTL)},
	}
	setParts := []string{"#ttl = :ttl"}
	if len(link.SessionTags) > 0 {
		tags, err := attributevalue.Marshal(link.SessionTags)
		if err != nil {
			return fmt.Errorf("failed to marshal creation-link tags: %w", err)
		}
		names["#tags"] = "session_tags"
		values[":tags"] = tags
		setParts = append(setParts, "#tags = :tags")
	}

	update := "SET " + strings.Join(setParts, ", ")
	if len(link.TargetSessionRefs) > 0 {
		names["#targets"] = "target_session_refs"
		values[":targets"] = &ddbtypes.AttributeValueMemberSS{Value: link.TargetSessionRefs}
		update += " ADD #targets :targets"
	}

	_, err := ddbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(tableName),
		Key:                       map[string]ddbtypes.AttributeValue{"pk": &ddbtypes.AttributeValueMemberS{Value: link.PK}},
		UpdateExpression:          aws.String(update),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	if err != nil {
		return fmt.Errorf("failed to write creation link: %w", err)
	}
	log.Printf("CREATION_LINK_WRITE: pk=%s tags=%d targets=%d", link.PK, len(link.SessionTags), len(link.TargetSessionRefs))
	return nil
}

// BatchGetIdentityLinks fetches identity link records for a set of PKs.
// Returns a map of pk -> DynamoDBIdentityLink for found records.
func BatchGetIdentityLinks(ctx context.Context, ddbClient LinkGetter, tableName string, pks []string) (map[string]*types.DynamoDBIdentityLink, error) {
	result := make(map[string]*types.DynamoDBIdentityLink)
	if len(pks) == 0 {
		return result, nil
	}

	collect := func(items []map[string]ddbtypes.AttributeValue) error {
		for _, item := range items {
			var link types.DynamoDBIdentityLink
			if err := attributevalue.UnmarshalMap(item, &link); err != nil {
				return fmt.Errorf("failed to unmarshal identity link: %w", err)
			}
			result[link.PK] = &link
		}
		return nil
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

		// BatchGetItem returns any keys it couldn't service (throttling) in
		// UnprocessedKeys; retry those with bounded exponential backoff so
		// throttled records aren't silently dropped.
		req := map[string]ddbtypes.KeysAndAttributes{
			tableName: {Keys: keys},
		}
		const maxAttempts = 5
		backoff := 50 * time.Millisecond
		for attempt := 0; ; attempt++ {
			out, err := ddbClient.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
				RequestItems: req,
			})
			if err != nil {
				return result, fmt.Errorf("batch get identity links failed: %w", err)
			}

			if err := collect(out.Responses[tableName]); err != nil {
				return result, err
			}

			unprocessed, ok := out.UnprocessedKeys[tableName]
			if !ok || len(unprocessed.Keys) == 0 {
				break
			}
			if attempt+1 >= maxAttempts {
				return result, fmt.Errorf("batch get identity links exhausted retries with %d unprocessed keys", len(unprocessed.Keys))
			}
			req = map[string]ddbtypes.KeysAndAttributes{
				tableName: unprocessed,
			}
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	return result, nil
}

// UpdateSessionTags attaches newly observed creation metadata to one exact
// session. It changes only session_tags and version, with an optimistic retry,
// so a concurrent activity write cannot be replaced by a stale full-item Put.
// A missing session is left alone; its creation# record remains available for
// a later activity batch.
func UpdateSessionTags(ctx context.Context, ddbClient SessionTagStore, tableName, customerID, sessionRef string, tags map[string]string) error {
	if len(tags) == 0 {
		return nil
	}
	personKey, sk, ok := strings.Cut(sessionRef, "|")
	if !ok || personKey == "" || sk == "" {
		return fmt.Errorf("invalid session ref: %s", sessionRef)
	}
	pk := customerID + "#" + personKey

	key := map[string]ddbtypes.AttributeValue{
		"pk": &ddbtypes.AttributeValueMemberS{Value: pk},
		"sk": &ddbtypes.AttributeValueMemberS{Value: sk},
	}
	const maxAttempts = 4
	for attempt := 0; attempt < maxAttempts; attempt++ {
		getOut, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
			TableName:      aws.String(tableName),
			Key:            key,
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return fmt.Errorf("failed to get session %s for tag update: %w", sessionRef, err)
		}
		if len(getOut.Item) == 0 {
			log.Printf("SESSION_TAG_UPDATE: session not yet in DDB, skipping update for %s", sessionRef)
			return nil
		}

		var existing types.DynamoDBSession
		if err := attributevalue.UnmarshalMap(getOut.Item, &existing); err != nil {
			return fmt.Errorf("failed to unmarshal session %s for tag update: %w", sessionRef, err)
		}
		merged := mergeSessionTags(existing.SessionTags, tags)
		if len(merged) == len(existing.SessionTags) {
			return nil
		}
		marshaledTags, err := attributevalue.Marshal(merged)
		if err != nil {
			return fmt.Errorf("failed to marshal tags for session %s: %w", sessionRef, err)
		}
		_, err = ddbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:           aws.String(tableName),
			Key:                 key,
			UpdateExpression:    aws.String("SET #tags = :tags, #version = :next"),
			ConditionExpression: aws.String("attribute_exists(pk) AND (attribute_not_exists(#version) OR #version = :expected)"),
			ExpressionAttributeNames: map[string]string{
				"#tags":    "session_tags",
				"#version": "version",
			},
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":tags":     marshaledTags,
				":expected": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", existing.Version)},
				":next":     &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", existing.Version+1)},
			},
		})
		if err == nil {
			log.Printf("SESSION_TAG_UPDATE: updated session=%s tags=%d", sessionRef, len(tags))
			return nil
		}
		var conflict *ddbtypes.ConditionalCheckFailedException
		if !errors.As(err, &conflict) {
			return fmt.Errorf("failed to update session %s tags: %w", sessionRef, err)
		}
	}
	return fmt.Errorf("failed to update session %s tags after %d concurrent writes", sessionRef, maxAttempts)
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

// UpdateParentSessionGrants records a granted (aws login / MCP) session ref on
// its authorizing session — the symmetric side of the child's
// agent_authorized_by_session / login_granted_by_session — when the authorizer
// was ingested in a prior Lambda invocation.
func UpdateParentSessionGrants(ctx context.Context, ddbClient SessionStore, tableName, customerID, parentRef, childRef string) error {
	personKey, sk, ok := strings.Cut(parentRef, "|")
	if !ok || personKey == "" || sk == "" {
		return fmt.Errorf("invalid authorizing session ref: %s", parentRef)
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
		return fmt.Errorf("failed to get authorizing session %s: %w", parentRef, err)
	}
	if len(getOut.Item) == 0 {
		// Authorizer not yet in DDB — a later batch's merge will attribute it.
		log.Printf("GRANT_PARENT_UPDATE: authorizing session not yet in DDB, skipping update for %s", parentRef)
		return nil
	}

	var existing types.DynamoDBSession
	if err := attributevalue.UnmarshalMap(getOut.Item, &existing); err != nil {
		return fmt.Errorf("failed to unmarshal authorizing session %s: %w", parentRef, err)
	}

	existing.GrantedSessionRefs = MergeUniqueStrings(existing.GrantedSessionRefs, []string{childRef})
	existing.Version++

	item, err := attributevalue.MarshalMap(&existing)
	if err != nil {
		return fmt.Errorf("failed to marshal updated authorizing session %s: %w", parentRef, err)
	}
	if _, err := ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	}); err != nil {
		return fmt.Errorf("failed to write updated authorizing session %s: %w", parentRef, err)
	}

	log.Printf("GRANT_PARENT_UPDATE: updated authorizer=%s with granted=%s", parentRef, childRef)
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
