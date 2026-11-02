// Relation records and exact distinct-count summaries.
package dynamodb

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
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

	RelationSummarySK = "_summary"
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

// RelationWriteResult reports what one WriteRelations call created. It can be
// non-empty alongside an error: items written before the failure stay written.
type RelationWriteResult struct {
	// NewSubjects holds the subject PKs whose _summary this call created, which
	// marks the noun's first appearance anywhere.
	NewSubjects map[string]bool
	// NewEdges holds the edges this call created, in key order. An edge that
	// already existed only had its bounds widened and is absent.
	NewEdges []types.DynamoDBRelation
}

// WriteRelations deduplicates and writes directed edges in key order.
func WriteRelations(ctx context.Context, store RelationStore, tableName string, relations []types.DynamoDBRelation) (RelationWriteResult, error) {
	result := RelationWriteResult{NewSubjects: make(map[string]bool)}
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
	for _, key := range keys {
		if err := validateRelation(merged[key]); err != nil {
			return result, err
		}
	}

	// One batched read tells which edges and summaries already exist, so a
	// known edge whose bounds did not move costs half a read unit instead of
	// a cancelled transaction, a failed conditional put, a consistent read,
	// and two boundary updates. A failed read only loses the shortcut: every edge then takes
	// the create-if-absent path, which is correct on its own.
	stored, summaries, err := prefetchRelations(ctx, store, tableName, merged, keys)
	if err != nil {
		log.Printf("WARNING: relation prefetch failed, writing every edge: %v", err)
		stored, summaries = nil, make(map[string]bool)
	}

	for _, key := range keys {
		relation := merged[key]
		if prior, ok := stored[key]; ok {
			if err := refreshRelationBounds(ctx, store, tableName, relation, prior); err != nil {
				return result, err
			}
			continue
		}
		if !summaries[relation.PK] {
			created, err := ensureRelationSummary(ctx, store, tableName, relation)
			if err != nil {
				return result, err
			}
			if created {
				result.NewSubjects[relation.PK] = true
			}
			summaries[relation.PK] = true
		}
		created, err := writeRelation(ctx, store, tableName, relation)
		if err != nil {
			return result, err
		}
		if created {
			result.NewEdges = append(result.NewEdges, relation)
		}
	}
	return result, nil
}

// relationBounds is the stored first and last observation of one edge.
type relationBounds struct {
	FirstSeen string `dynamodbav:"first_seen"`
	LastSeen  string `dynamodbav:"last_seen"`
}

// refreshRelationBounds widens a known edge's bounds only when they move:
// first_seen when the batch saw the pair earlier, last_seen when it saw it
// later. Each update is still conditional, so a stale prefetch can only cause
// a rejected no-op, never a regression.
func refreshRelationBounds(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation, prior relationBounds) error {
	if relation.FirstSeen != "" && (prior.FirstSeen == "" || relation.FirstSeen < prior.FirstSeen) {
		if err := updateRelationBoundary(ctx, store, tableName, relation, "first_seen", relation.FirstSeen, ">"); err != nil {
			return err
		}
	}
	if relation.LastSeen != "" && relation.LastSeen > prior.LastSeen {
		if err := updateRelationBoundary(ctx, store, tableName, relation, "last_seen", relation.LastSeen, "<"); err != nil {
			return err
		}
	}
	return nil
}

// prefetchRelations batch-reads the edges and their subjects' summaries,
// returning the bounds of edges that exist (by merged key) and the set of PKs
// whose _summary exists. Reads are eventually consistent: a miss falls back to
// the conditional create path, which handles an edge that does exist.
func prefetchRelations(ctx context.Context, store RelationStore, tableName string, merged map[string]types.DynamoDBRelation, keys []string) (map[string]relationBounds, map[string]bool, error) {
	stored := make(map[string]relationBounds)
	summaries := make(map[string]bool)
	var reqKeys []map[string]ddbtypes.AttributeValue
	seenPK := make(map[string]bool)
	for _, key := range keys {
		relation := merged[key]
		reqKeys = append(reqKeys, relationKey(relation.PK, relation.SK))
		if !seenPK[relation.PK] {
			seenPK[relation.PK] = true
			reqKeys = append(reqKeys, relationSummaryKey(relation.PK))
		}
	}
	const batchSize = 100
	for start := 0; start < len(reqKeys); start += batchSize {
		end := min(start+batchSize, len(reqKeys))
		req := map[string]ddbtypes.KeysAndAttributes{tableName: {
			Keys:                     reqKeys[start:end],
			ProjectionExpression:     aws.String("#pk, #sk, #fs, #ls"),
			ExpressionAttributeNames: map[string]string{"#pk": "pk", "#sk": "sk", "#fs": "first_seen", "#ls": "last_seen"},
		}}
		for attempt := 0; len(req) > 0; attempt++ {
			if attempt > 0 {
				if attempt >= transactionMaxAttempts {
					return nil, nil, fmt.Errorf("relation prefetch: unprocessed keys after %d attempts", attempt)
				}
				if err := waitForTransactionRetry(ctx, attempt); err != nil {
					return nil, nil, err
				}
			}
			out, err := store.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: req})
			if err != nil {
				return nil, nil, err
			}
			for _, item := range out.Responses[tableName] {
				pk, sk := stringAttr(item, "pk"), stringAttr(item, "sk")
				if sk == RelationSummarySK {
					summaries[pk] = true
					continue
				}
				var bounds relationBounds
				if err := attributevalue.UnmarshalMap(item, &bounds); err != nil {
					return nil, nil, err
				}
				stored[pk+"\x00"+sk] = bounds
			}
			req = out.UnprocessedKeys
		}
	}
	return stored, summaries, nil
}

// WriteRelation creates an edge and increments its subject summary exactly
// once, reporting whether the edge is new. A replay updates the edge bounds
// without changing the summary.
func WriteRelation(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation) (bool, error) {
	if err := validateRelation(relation); err != nil {
		return false, err
	}
	if _, err := ensureRelationSummary(ctx, store, tableName, relation); err != nil {
		return false, err
	}
	return writeRelation(ctx, store, tableName, relation)
}

// writeRelation reports true when its put created the edge, false when the
// edge already existed and only its bounds were widened.
func writeRelation(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation) (bool, error) {
	item, err := attributevalue.MarshalMap(relation)
	if err != nil {
		return false, fmt.Errorf("marshal relation: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < transactionMaxAttempts; attempt++ {
		if attempt > 0 {
			if err := waitForTransactionRetry(ctx, attempt); err != nil {
				return false, err
			}
		}
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
						"#kind":   RelationCountName(relation.RelatedKind),
					},
					ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
						":one": &ddbtypes.AttributeValueMemberN{Value: "1"},
					},
				}},
			},
		})
		if err == nil {
			return true, nil
		}
		if !isTransactionCancellation(err) && !isTransactionConflict(err) {
			return false, fmt.Errorf("write relation %s/%s: %w", relation.PK, relation.SK, err)
		}
		lastErr = err

		existing, getErr := getRelation(ctx, store, tableName, relation.PK, relation.SK)
		if getErr != nil {
			return false, getErr
		}
		if existing != nil {
			return false, updateRelationBounds(ctx, store, tableName, relation)
		}
	}

	return false, fmt.Errorf("write relation %s/%s did not converge after %d attempts: %w",
		relation.PK, relation.SK, transactionMaxAttempts, lastErr)
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

// ensureRelationSummary creates the subject's _summary if it is missing and
// reports whether this call created it.
func ensureRelationSummary(ctx context.Context, store RelationStore, tableName string, relation types.DynamoDBRelation) (bool, error) {
	counts := make(map[string]int, len(relationKinds))
	for _, kind := range relationKinds {
		counts[RelationCountName(kind)] = 0
	}
	item, err := attributevalue.MarshalMap(types.DynamoDBRelationSummary{
		PK:         relation.PK,
		SK:         RelationSummarySK,
		CustomerID: relation.CustomerID,
		Counts:     counts,
	})
	if err != nil {
		return false, fmt.Errorf("marshal relation summary: %w", err)
	}

	err = retryTransactionConflict(ctx, func() error {
		_, err := store.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:           aws.String(tableName),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)"),
		})
		return err
	})
	if isConditionalCheckFailure(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create relation summary %s: %w", relation.PK, err)
	}
	return true, nil
}

// GetRelationSummaryCounts reads one noun's _summary counts, keyed by count
// name ("people", "accounts", ...). A missing summary reads as nil.
func GetRelationSummaryCounts(ctx context.Context, store RelationStore, tableName, pk string) (map[string]int, error) {
	// Consistent, because callers read right after their own increments.
	result, err := store.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(tableName),
		ConsistentRead: aws.Bool(true),
		Key:            relationSummaryKey(pk),
	})
	if err != nil {
		return nil, fmt.Errorf("get relation summary %s: %w", pk, err)
	}
	if len(result.Item) == 0 {
		return nil, nil
	}
	var summary types.DynamoDBRelationSummary
	if err := attributevalue.UnmarshalMap(result.Item, &summary); err != nil {
		return nil, fmt.Errorf("unmarshal relation summary %s: %w", pk, err)
	}
	return summary.Counts, nil
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
	err := retryTransactionConflict(ctx, func() error {
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
		return err
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

// RelationCountName is the _summary counts key for a related kind.
func RelationCountName(kind string) string {
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

func stringAttr(item map[string]ddbtypes.AttributeValue, name string) string {
	if v, ok := item[name].(*ddbtypes.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}
