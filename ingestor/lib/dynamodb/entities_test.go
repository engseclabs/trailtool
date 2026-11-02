package dynamodb

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

type fakeEntityStore struct {
	item map[string]ddbtypes.AttributeValue
}

func (s *fakeEntityStore) GetItem(_ context.Context, _ *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return &dynamodb.GetItemOutput{Item: s.item}, nil
}

func (s *fakeEntityStore) PutItem(_ context.Context, input *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	s.item = input.Item
	return &dynamodb.PutItemOutput{}, nil
}

func TestMergeAccountAggregatedIsOrderAndPartitionIndependent(t *testing.T) {
	a := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111", FirstSeen: "2026-07-03", LastSeen: "2026-07-03",
		EventsCount: 1, PeopleCount: 1, SessionsCount: 1,
		TopEventNames: map[string]int{"s3.amazonaws.com:GetObject": 1},
		ClickOpsCount: 1,
	}
	b := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111", AccountName: "production",
		FirstSeen: "2026-07-01", LastSeen: "2026-07-02", EventsCount: 2, RolesCount: 2,
		TotalDeniedEvents:   1,
		TopDeniedEventNames: map[string]int{"s3.amazonaws.com:DeleteObject": 1},
	}
	c := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111", AccountName: "production",
		FirstSeen: "2026-07-04", LastSeen: "2026-07-05", EventsCount: 3, ResourcesCount: 3,
		TopEventNames:       map[string]int{"s3.amazonaws.com:GetObject": 2},
		TotalDeniedEvents:   2,
		TopDeniedEventNames: map[string]int{"s3.amazonaws.com:DeleteObject": 2},
		ClickOpsCount:       2,
	}

	ab := MergeAccountAggregated(a, b)
	ba := MergeAccountAggregated(b, a)
	if !reflect.DeepEqual(ab, ba) {
		t.Fatalf("account merge depends on arrival order:\nab=%+v\nba=%+v", ab, ba)
	}
	left := MergeAccountAggregated(ab, c)
	right := MergeAccountAggregated(a, MergeAccountAggregated(b, c))
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("account merge depends on batch partition:\nleft=%+v\nright=%+v", left, right)
	}
	if left.EventsCount != 6 || left.FirstSeen != "2026-07-01" || left.LastSeen != "2026-07-05" {
		t.Fatalf("merged account = %+v, want 6 events spanning 2026-07-01 through 2026-07-05", left)
	}
	if left.TopEventNames["s3.amazonaws.com:GetObject"] != 3 ||
		left.TotalDeniedEvents != 3 ||
		left.TopDeniedEventNames["s3.amazonaws.com:DeleteObject"] != 3 ||
		left.ClickOpsCount != 3 {
		t.Fatalf("merged account activity = %+v", left)
	}
}

func TestWriteAccountToDynamoDBPreservesPriorBatches(t *testing.T) {
	store := &fakeEntityStore{}
	ctx := context.Background()
	first := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111",
		FirstSeen: "2026-07-01", LastSeen: "2026-07-01", EventsCount: 2,
	}
	second := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111",
		FirstSeen: "2026-07-02", LastSeen: "2026-07-02", EventsCount: 3,
	}

	if err := WriteAccountToDynamoDB(ctx, store, "accounts", first); err != nil {
		t.Fatalf("write first batch: %v", err)
	}
	if err := WriteAccountToDynamoDB(ctx, store, "accounts", second); err != nil {
		t.Fatalf("write second batch: %v", err)
	}

	var got types.DynamoDBAccount
	if err := attributevalue.UnmarshalMap(store.item, &got); err != nil {
		t.Fatalf("unmarshal stored account: %v", err)
	}
	if got.EventsCount != 5 || got.FirstSeen != "2026-07-01" || got.LastSeen != "2026-07-02" {
		t.Fatalf("stored account = %+v, want 5 events spanning both batches", got)
	}
}

func TestMergeResourceAggregatedIsOrderIndependent(t *testing.T) {
	a := &types.DynamoDBResource{
		CustomerID:  "test",
		ResourceKey: "111111111111#key",
		Identifier:  "s3:bucket:example",
		Type:        "unknown",
		AccountID:   "111111111111",
		TotalEvents: 1,
		RolesUsing:  []string{"role-b"},
		ServicesUsed: []string{
			"s3.amazonaws.com",
		},
		FirstSeen: "2026-07-02",
		LastSeen:  "2026-07-02",
	}
	b := &types.DynamoDBResource{
		CustomerID:  "test",
		ResourceKey: "111111111111#key",
		Identifier:  "s3:bucket:example",
		Type:        "s3:bucket",
		Name:        "example",
		ARN:         "arn:aws:s3:::example",
		AccountID:   "111111111111",
		TotalEvents: 2,
		RolesUsing:  []string{"role-a"},
		ServicesUsed: []string{
			"s3-control.amazonaws.com",
		},
		FirstSeen: "2026-07-01",
		LastSeen:  "2026-07-03",
	}

	ab := MergeResourceAggregated(a, b)
	ba := MergeResourceAggregated(b, a)
	if !reflect.DeepEqual(ab, ba) {
		t.Fatalf("resource merge depends on arrival order:\nab=%+v\nba=%+v", ab, ba)
	}
	if ab.Type != "s3:bucket" || ab.TotalEvents != 3 || ab.RolesCount != 2 {
		t.Fatalf("merged resource = %+v", ab)
	}
}

func TestMergePersonPreservesDeniedActivity(t *testing.T) {
	got := MergePerson(
		&types.DynamoDBPerson{
			PersonKey:           "email#test-user@example.invalid",
			DeniedEventCount:    1,
			TopDeniedEventNames: map[string]int{"s3.amazonaws.com:GetObject": 1},
		},
		&types.DynamoDBPerson{
			PersonKey:           "email#test-user@example.invalid",
			DeniedEventCount:    2,
			TopDeniedEventNames: map[string]int{"s3.amazonaws.com:GetObject": 2},
		},
	)
	if got.DeniedEventCount != 3 || got.TopDeniedEventNames["s3.amazonaws.com:GetObject"] != 3 {
		t.Fatalf("merged person denied activity = %+v", got)
	}
}

func TestMergeResourceDoesNotAddDistinctCounts(t *testing.T) {
	resource := MergeResourceAggregated(
		&types.DynamoDBResource{
			ResourceKey:   "111111111111#key",
			Identifier:    "s3:bucket:example",
			AccountID:     "111111111111",
			PeopleCount:   4,
			SessionsCount: 3,
		},
		&types.DynamoDBResource{
			ResourceKey:   "111111111111#key",
			Identifier:    "s3:bucket:example",
			AccountID:     "111111111111",
			PeopleCount:   2,
			SessionsCount: 5,
		},
	)
	if resource.PeopleCount != 4 || resource.SessionsCount != 5 {
		t.Fatalf("resource relationship counts = %d/%d, want 4/5",
			resource.PeopleCount, resource.SessionsCount)
	}
}
