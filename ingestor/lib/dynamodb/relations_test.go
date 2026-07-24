package dynamodb

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

type fakeRelationStore struct {
	edges               map[string]types.DynamoDBRelation
	summaries           map[string]types.DynamoDBRelationSummary
	transactionCalls    int
	transactionFailures int
}

func newFakeRelationStore() *fakeRelationStore {
	return &fakeRelationStore{
		edges:     make(map[string]types.DynamoDBRelation),
		summaries: make(map[string]types.DynamoDBRelationSummary),
	}
}

func relationItemKey(item map[string]ddbtypes.AttributeValue) string {
	pk := item["pk"].(*ddbtypes.AttributeValueMemberS).Value
	sk := item["sk"].(*ddbtypes.AttributeValueMemberS).Value
	return pk + "\x00" + sk
}

func relationInputKey(key map[string]ddbtypes.AttributeValue) string {
	pk := key["pk"].(*ddbtypes.AttributeValueMemberS).Value
	sk := key["sk"].(*ddbtypes.AttributeValueMemberS).Value
	return pk + "\x00" + sk
}

func (s *fakeRelationStore) GetItem(_ context.Context, input *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	edge, ok := s.edges[relationInputKey(input.Key)]
	if !ok {
		return &dynamodb.GetItemOutput{}, nil
	}
	item, err := attributevalue.MarshalMap(edge)
	if err != nil {
		return nil, err
	}
	return &dynamodb.GetItemOutput{Item: item}, nil
}

func (s *fakeRelationStore) PutItem(_ context.Context, input *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	sk := input.Item["sk"].(*ddbtypes.AttributeValueMemberS).Value
	if sk == RelationSummarySK {
		var summary types.DynamoDBRelationSummary
		if err := attributevalue.UnmarshalMap(input.Item, &summary); err != nil {
			return nil, err
		}
		if _, exists := s.summaries[summary.PK]; exists && input.ConditionExpression != nil {
			return nil, &ddbtypes.ConditionalCheckFailedException{Message: stringPointer("exists")}
		}
		s.summaries[summary.PK] = summary
		return &dynamodb.PutItemOutput{}, nil
	}

	var edge types.DynamoDBRelation
	if err := attributevalue.UnmarshalMap(input.Item, &edge); err != nil {
		return nil, err
	}
	s.edges[relationItemKey(input.Item)] = edge
	return &dynamodb.PutItemOutput{}, nil
}

func (s *fakeRelationStore) UpdateItem(_ context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	key := relationInputKey(input.Key)
	edge, ok := s.edges[key]
	if !ok {
		return nil, fmt.Errorf("edge %q not found", key)
	}
	name := input.ExpressionAttributeNames["#boundary"]
	value := input.ExpressionAttributeValues[":value"].(*ddbtypes.AttributeValueMemberS).Value
	switch name {
	case "first_seen":
		if edge.FirstSeen != "" && edge.FirstSeen <= value {
			return nil, &ddbtypes.ConditionalCheckFailedException{Message: stringPointer("not earlier")}
		}
		edge.FirstSeen = value
	case "last_seen":
		if edge.LastSeen != "" && edge.LastSeen >= value {
			return nil, &ddbtypes.ConditionalCheckFailedException{Message: stringPointer("not later")}
		}
		edge.LastSeen = value
	default:
		return nil, fmt.Errorf("unexpected boundary %q", name)
	}
	s.edges[key] = edge
	return &dynamodb.UpdateItemOutput{}, nil
}

func (s *fakeRelationStore) TransactWriteItems(_ context.Context, input *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	s.transactionCalls++
	if s.transactionFailures > 0 {
		s.transactionFailures--
		return nil, &ddbtypes.TransactionCanceledException{Message: stringPointer("retry")}
	}

	put := input.TransactItems[0].Put
	key := relationItemKey(put.Item)
	if _, exists := s.edges[key]; exists {
		return nil, &ddbtypes.TransactionCanceledException{Message: stringPointer("edge exists")}
	}

	var edge types.DynamoDBRelation
	if err := attributevalue.UnmarshalMap(put.Item, &edge); err != nil {
		return nil, err
	}
	update := input.TransactItems[1].Update
	summaryPK := update.Key["pk"].(*ddbtypes.AttributeValueMemberS).Value
	summary, exists := s.summaries[summaryPK]
	if !exists {
		return nil, fmt.Errorf("summary %q not found", summaryPK)
	}
	countName := update.ExpressionAttributeNames["#kind"]
	increment, err := strconv.Atoi(update.ExpressionAttributeValues[":one"].(*ddbtypes.AttributeValueMemberN).Value)
	if err != nil {
		return nil, err
	}

	s.edges[key] = edge
	summary.Counts[countName] += increment
	s.summaries[summaryPK] = summary
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func stringPointer(value string) *string {
	return &value
}

func TestNewRelationEncodesKeysAndPreservesRawIDs(t *testing.T) {
	subjectID := "arn:aws:iam::111111111111:role/path/reader"
	relatedID := "person#with|delimiters"
	relation := NewRelation(
		"test",
		RelationKindRole,
		subjectID,
		RelationKindPerson,
		relatedID,
		"2026-07-24T10:00:00Z",
	)

	if relation.SubjectID != subjectID || relation.RelatedID != relatedID {
		t.Fatalf("raw IDs changed: %+v", relation)
	}
	if relation.PK == "test#role#"+subjectID || relation.SK == "person#"+relatedID {
		t.Fatalf("relation keys contain unencoded IDs: %+v", relation)
	}
	if err := validateRelation(relation); err != nil {
		t.Fatalf("valid relation rejected: %v", err)
	}
}

func TestWriteRelationCountsAnEdgeOnceAndExtendsBounds(t *testing.T) {
	store := newFakeRelationStore()
	edge := NewRelation(
		"test",
		RelationKindAccount,
		"111111111111",
		RelationKindService,
		"s3.amazonaws.com",
		"2026-07-24T10:00:00Z",
	)
	if err := WriteRelation(context.Background(), store, "relations", edge); err != nil {
		t.Fatalf("create relation: %v", err)
	}

	replayed := edge
	replayed.FirstSeen = "2026-07-23T09:00:00Z"
	replayed.LastSeen = "2026-07-25T11:00:00Z"
	if err := WriteRelation(context.Background(), store, "relations", replayed); err != nil {
		t.Fatalf("replay relation: %v", err)
	}

	got := store.edges[edge.PK+"\x00"+edge.SK]
	if got.FirstSeen != replayed.FirstSeen || got.LastSeen != replayed.LastSeen {
		t.Fatalf("bounds = %s/%s, want %s/%s",
			got.FirstSeen, got.LastSeen, replayed.FirstSeen, replayed.LastSeen)
	}
	summary := store.summaries[edge.PK]
	if summary.Counts["services"] != 1 {
		t.Fatalf("service count = %d, want 1", summary.Counts["services"])
	}
}

func TestWriteRelationRetriesMissingEdgeAfterTransactionConflict(t *testing.T) {
	store := newFakeRelationStore()
	store.transactionFailures = 1
	edge := NewRelation(
		"test",
		RelationKindPerson,
		"idc#d-123#user-456",
		RelationKindRole,
		"arn:aws:iam::111111111111:role/reader",
		"2026-07-24T10:00:00Z",
	)

	if err := WriteRelation(context.Background(), store, "relations", edge); err != nil {
		t.Fatalf("write relation: %v", err)
	}
	if store.transactionCalls != 2 {
		t.Fatalf("transaction calls = %d, want 2", store.transactionCalls)
	}
	if store.summaries[edge.PK].Counts["roles"] != 1 {
		t.Fatalf("role count = %d, want 1", store.summaries[edge.PK].Counts["roles"])
	}
}

func TestWriteRelationsDeduplicatesAndCountsInverseEdges(t *testing.T) {
	store := newFakeRelationStore()
	forward := NewRelation(
		"test",
		RelationKindService,
		"s3.amazonaws.com",
		RelationKindResource,
		"s3:bucket:logs",
		"2026-07-24T10:00:00Z",
	)
	duplicate := forward
	duplicate.LastSeen = "2026-07-24T11:00:00Z"
	inverse := NewRelation(
		"test",
		RelationKindResource,
		"s3:bucket:logs",
		RelationKindService,
		"s3.amazonaws.com",
		"2026-07-24T10:00:00Z",
	)

	if err := WriteRelations(context.Background(), store, "relations", []types.DynamoDBRelation{
		forward,
		duplicate,
		inverse,
	}); err != nil {
		t.Fatalf("write relations: %v", err)
	}
	if len(store.edges) != 2 {
		t.Fatalf("edge count = %d, want 2", len(store.edges))
	}
	if store.summaries[forward.PK].Counts["resources"] != 1 {
		t.Fatalf("service resource count = %d, want 1", store.summaries[forward.PK].Counts["resources"])
	}
	if store.summaries[inverse.PK].Counts["services"] != 1 {
		t.Fatalf("resource service count = %d, want 1", store.summaries[inverse.PK].Counts["services"])
	}
	if store.edges[forward.PK+"\x00"+forward.SK].LastSeen != duplicate.LastSeen {
		t.Fatalf("deduplicated edge did not retain the latest observation")
	}
}
