// Relation records and exact distinct-count summaries.
package dynamodb

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const (
	RelationKindPerson   = "person"
	RelationKindSession  = "session"
	RelationKindAccount  = "account"
	RelationKindRole     = "role"
	RelationKindService  = "service"
	RelationKindResource = "resource"

	RelationSummarySK  = "_summary"
	relationMaxRetries = 3
)

var relationKinds = []string{
	RelationKindPerson,
	RelationKindSession,
	RelationKindAccount,
	RelationKindRole,
	RelationKindService,
	RelationKindResource,
}

// NewRelation builds one directed edge. IDs are encoded in keys and retained
// verbatim in attributes for display.
func NewRelation(customerID, subjectKind, subjectID, relatedKind, relatedID, observedAt string) types.DynamoDBRelation {
	return types.DynamoDBRelation{
		PK:          RelationPK(customerID, subjectKind, subjectID),
		SK:          relationSK(relatedKind, relatedID),
		CustomerID:  customerID,
		SubjectKind: subjectKind,
		SubjectID:   subjectID,
		RelatedKind: relatedKind,
		RelatedID:   relatedID,
		FirstSeen:   observedAt,
		LastSeen:    observedAt,
	}
}

// RelationPK returns the partition key for one noun.
func RelationPK(customerID, kind, id string) string {
	return customerID + "#" + kind + "#" + encodeRelationID(id)
}

func relationSK(kind, id string) string {
	return kind + "#" + encodeRelationID(id)
}

func encodeRelationID(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id))
}

// WriteRelations deduplicates and writes directed edges in key order.
func WriteRelations(ctx context.Context, store RelationStore, tableName string, relations []types.DynamoDBRelation) error {
	merged := make(map[string]types.DynamoDBRelation)
	for _, relation := range relations {
		if relation.SubjectID == "" || relation.RelatedID == "" {
			continue
		}
		key := relation.PK + "\x00" + relation.SK
		if existing, ok := merged[key]; ok {
			existing.FirstSeen = earliestNonEmpty(existing.FirstSeen, relation.FirstSeen)
			existing.LastSeen = latestNonEmpty(existing.LastSeen, relation.LastSeen)
			merged[key] = existing
		} else {
			merged[key] = relation
		}
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	summaries := make(map[string]bool)
	for _, key := range keys {
		relation := merged[key]
		if err := validateRelation(relation); err != nil {
			return err
		}
		if !summaries[relation.PK] {
			if err := ensureRelationSummary(ctx, store, tableName, relation); err != nil {
				return err
			}
			summaries[relation.PK] = true
		}
		if err := writeRelation(ctx, store, tableName, relation); err != nil {
			return err
		}
	}
	return nil
}

// WriteRelation creates an edge and increments its subject summary exactly
// once. A replay updates the edge bounds without changing the summary.
func WriteRelation(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation) error {
	if err := validateRelation(relation); err != nil {
		return err
	}
	if err := ensureRelationSummary(ctx, store, tableName, relation); err != nil {
		return err
	}
	return writeRelation(ctx, store, tableName, relation)
}

func writeRelation(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation) error {
	item, err := attributevalue.MarshalMap(relation)
	if err != nil {
		return fmt.Errorf("marshal relation: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= relationMaxRetries; attempt++ {
		_, err = store.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
			TransactItems: []ddbtypes.TransactWriteItem{
				{Put: &ddbtypes.Put{
					TableName:           aws.String(tableName),
					Item:                item,
					ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)"),
				}},
				{Update: &ddbtypes.Update{
					TableName:        aws.String(tableName),
					Key:              relationSummaryKey(relation.PK),
					UpdateExpression: aws.String("SET #counts.#kind = #counts.#kind + :one"),
					ExpressionAttributeNames: map[string]string{
						"#counts": "counts",
						"#kind":   relationCountName(relation.RelatedKind),
					},
					ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
						":one": &ddbtypes.AttributeValueMemberN{Value: "1"},
					},
				}},
			},
		})
		if err == nil {
			return nil
		}
		if !isTransactionCancellation(err) {
			return fmt.Errorf("write relation %s/%s: %w", relation.PK, relation.SK, err)
		}
		lastErr = err

		existing, getErr := getRelation(ctx, store, tableName, relation.PK, relation.SK)
		if getErr != nil {
			return getErr
		}
		if existing != nil {
			return updateRelationBounds(ctx, store, tableName, relation)
		}
	}

	return fmt.Errorf("write relation %s/%s did not converge after %d retries: %w",
		relation.PK, relation.SK, relationMaxRetries, lastErr)
}

func validateRelation(relation types.DynamoDBRelation) error {
	if relation.CustomerID == "" || relation.SubjectID == "" || relation.RelatedID == "" {
		return fmt.Errorf("relation customer, subject, and related IDs are required")
	}
	if !validRelationKind(relation.SubjectKind) || !validRelationKind(relation.RelatedKind) {
		return fmt.Errorf("invalid relation kinds %q and %q", relation.SubjectKind, relation.RelatedKind)
	}
	if relation.SubjectKind == relation.RelatedKind {
		return fmt.Errorf("same-kind relation %q is not supported", relation.SubjectKind)
	}
	if relation.PK != RelationPK(relation.CustomerID, relation.SubjectKind, relation.SubjectID) ||
		relation.SK != relationSK(relation.RelatedKind, relation.RelatedID) {
		return fmt.Errorf("relation keys do not match their raw IDs")
	}
	return nil
}

func validRelationKind(kind string) bool {
	for _, candidate := range relationKinds {
		if kind == candidate {
			return true
		}
	}
	return false
}

func ensureRelationSummary(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation) error {
	counts := make(map[string]int, len(relationKinds))
	for _, kind := range relationKinds {
		counts[relationCountName(kind)] = 0
	}
	item, err := attributevalue.MarshalMap(types.DynamoDBRelationSummary{
		PK:         relation.PK,
		SK:         RelationSummarySK,
		CustomerID: relation.CustomerID,
		Counts:     counts,
	})
	if err != nil {
		return fmt.Errorf("marshal relation summary: %w", err)
	}

	_, err = store.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)"),
	})
	if err != nil && !isConditionalCheckFailure(err) {
		return fmt.Errorf("create relation summary %s: %w", relation.PK, err)
	}
	return nil
}

func getRelation(ctx context.Context, store RelationStore, tableName, pk, sk string) (*types.DynamoDBRelation, error) {
	result, err := store.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(tableName),
		ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{
			"pk": &ddbtypes.AttributeValueMemberS{Value: pk},
			"sk": &ddbtypes.AttributeValueMemberS{Value: sk},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("get relation %s/%s: %w", pk, sk, err)
	}
	if len(result.Item) == 0 {
		return nil, nil
	}
	var relation types.DynamoDBRelation
	if err := attributevalue.UnmarshalMap(result.Item, &relation); err != nil {
		return nil, fmt.Errorf("unmarshal relation %s/%s: %w", pk, sk, err)
	}
	return &relation, nil
}

func updateRelationBounds(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation) error {
	if relation.FirstSeen != "" {
		if err := updateRelationBoundary(ctx, store, tableName, relation, "first_seen", relation.FirstSeen, ">"); err != nil {
			return err
		}
	}
	if relation.LastSeen != "" {
		if err := updateRelationBoundary(ctx, store, tableName, relation, "last_seen", relation.LastSeen, "<"); err != nil {
			return err
		}
	}
	return nil
}

func updateRelationBoundary(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation, name, value, comparison string) error {
	_, err := store.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(tableName),
		Key:              relationKey(relation.PK, relation.SK),
		UpdateExpression: aws.String("SET #boundary = :value"),
		ConditionExpression: aws.String(
			"attribute_not_exists(#boundary) OR #boundary " + comparison + " :value",
		),
		ExpressionAttributeNames: map[string]string{
			"#boundary": name,
		},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":value": &ddbtypes.AttributeValueMemberS{Value: value},
		},
	})
	if err != nil && !isConditionalCheckFailure(err) {
		return fmt.Errorf("update relation %s boundary: %w", name, err)
	}
	return nil
}

func relationKey(pk, sk string) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{
		"pk": &ddbtypes.AttributeValueMemberS{Value: pk},
		"sk": &ddbtypes.AttributeValueMemberS{Value: sk},
	}
}

func relationSummaryKey(pk string) map[string]ddbtypes.AttributeValue {
	return relationKey(pk, RelationSummarySK)
}

func relationCountName(kind string) string {
	if kind == RelationKindPerson {
		return "people"
	}
	return kind + "s"
}

func isConditionalCheckFailure(err error) bool {
	var target *ddbtypes.ConditionalCheckFailedException
	return errors.As(err, &target)
}

func isTransactionCancellation(err error) bool {
	var target *ddbtypes.TransactionCanceledException
	return errors.As(err, &target)
}
