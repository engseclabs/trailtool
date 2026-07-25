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

func TestMergeServiceAggregatedIsOrderIndependent(t *testing.T) {
	a := &types.DynamoDBService{
		CustomerID:          "test",
		EventSource:         "s3.amazonaws.com",
		DisplayName:         "Amazon S3",
		Category:            "Storage",
		TotalEvents:         2,
		RolesUsing:          []string{"role-b", "role-a"},
		ResourcesUsed:       []string{"s3:bucket:one"},
		TopEventNames:       map[string]int{"GetObject": 2},
		FirstSeen:           "2026-07-03",
		LastSeen:            "2026-07-04",
		TotalDeniedEvents:   1,
		TopDeniedEventNames: map[string]int{"PutObject": 1},
		PeopleCount:         2,
		SessionsCount:       1,
		AccountsCount:       1,
	}
	b := &types.DynamoDBService{
		CustomerID:          "test",
		EventSource:         "s3.amazonaws.com",
		DisplayName:         "Amazon S3",
		Category:            "Storage",
		TotalEvents:         3,
		RolesUsing:          []string{"role-c", "role-a"},
		ResourcesUsed:       []string{"s3:bucket:two", "s3:bucket:one"},
		TopEventNames:       map[string]int{"GetObject": 1, "ListBuckets": 2},
		FirstSeen:           "2026-07-01",
		LastSeen:            "2026-07-05",
		TotalDeniedEvents:   2,
		TopDeniedEventNames: map[string]int{"PutObject": 2},
		PeopleCount:         1,
		SessionsCount:       3,
		AccountsCount:       1,
	}

	ab := MergeServiceAggregated(a, b)
	ba := MergeServiceAggregated(b, a)
	if !reflect.DeepEqual(ab, ba) {
		t.Fatalf("service merge depends on arrival order:\nab=%+v\nba=%+v", ab, ba)
	}
	if ab.TotalEvents != 5 || ab.TotalDeniedEvents != 3 {
		t.Fatalf("event totals = %d/%d, want 5/3", ab.TotalEvents, ab.TotalDeniedEvents)
	}
	if ab.FirstSeen != "2026-07-01" || ab.LastSeen != "2026-07-05" {
		t.Fatalf("bounds = %s/%s, want 2026-07-01/2026-07-05", ab.FirstSeen, ab.LastSeen)
	}
	if ab.RolesCount != 3 || ab.ResourcesCount != 2 {
		t.Fatalf("role/resource counts = %d/%d, want 3/2", ab.RolesCount, ab.ResourcesCount)
	}
}

func TestMergeServiceAggregatedIsPartitionIndependent(t *testing.T) {
	a := &types.DynamoDBService{
		CustomerID: "test", EventSource: "ec2.amazonaws.com", TotalEvents: 1,
		TopEventNames: map[string]int{"RunInstances": 1}, FirstSeen: "2026-07-03", LastSeen: "2026-07-03",
	}
	b := &types.DynamoDBService{
		CustomerID: "test", EventSource: "ec2.amazonaws.com", TotalEvents: 2,
		TopEventNames: map[string]int{"DescribeInstances": 2}, FirstSeen: "2026-07-01", LastSeen: "2026-07-02",
	}
	c := &types.DynamoDBService{
		CustomerID: "test", EventSource: "ec2.amazonaws.com", TotalEvents: 3,
		TopEventNames: map[string]int{"RunInstances": 3}, FirstSeen: "2026-07-04", LastSeen: "2026-07-05",
	}

	left := MergeServiceAggregated(MergeServiceAggregated(a, b), c)
	right := MergeServiceAggregated(a, MergeServiceAggregated(b, c))
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("service merge depends on batch partition:\nleft=%+v\nright=%+v", left, right)
	}
}

func TestWriteServiceToDynamoDBPreservesPriorBatches(t *testing.T) {
	store := &fakeEntityStore{}
	ctx := context.Background()
	first := &types.DynamoDBService{
		CustomerID: "test", EventSource: "s3.amazonaws.com", TotalEvents: 2,
		RolesUsing: []string{"role-a"}, ResourcesUsed: []string{"s3:bucket:one"},
		TopEventNames: map[string]int{"GetObject": 2}, FirstSeen: "2026-07-01", LastSeen: "2026-07-01",
	}
	second := &types.DynamoDBService{
		CustomerID: "test", EventSource: "s3.amazonaws.com", TotalEvents: 1,
		RolesUsing: []string{"role-b"}, ResourcesUsed: []string{"s3:bucket:two"},
		TopEventNames: map[string]int{"ListBuckets": 1}, FirstSeen: "2026-07-02", LastSeen: "2026-07-02",
	}

	if err := WriteServiceToDynamoDB(ctx, store, "services", first); err != nil {
		t.Fatalf("write first batch: %v", err)
	}
	if err := WriteServiceToDynamoDB(ctx, store, "services", second); err != nil {
		t.Fatalf("write second batch: %v", err)
	}

	var got types.DynamoDBService
	if err := attributevalue.UnmarshalMap(store.item, &got); err != nil {
		t.Fatalf("unmarshal stored service: %v", err)
	}
	if got.TotalEvents != 3 || got.RolesCount != 2 || got.ResourcesCount != 2 {
		t.Fatalf("stored service totals = events:%d roles:%d resources:%d, want 3/2/2", got.TotalEvents, got.RolesCount, got.ResourcesCount)
	}
}

func TestMergeAccountAggregatedIsOrderAndPartitionIndependent(t *testing.T) {
	a := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111", FirstSeen: "2026-07-03", LastSeen: "2026-07-03",
		EventsCount: 1, PeopleCount: 1, SessionsCount: 1,
	}
	b := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111", AccountName: "production",
		FirstSeen: "2026-07-01", LastSeen: "2026-07-02", EventsCount: 2, RolesCount: 2,
	}
	c := &types.DynamoDBAccount{
		CustomerID: "test", AccountID: "111111111111", AccountName: "production",
		FirstSeen: "2026-07-04", LastSeen: "2026-07-05", EventsCount: 3, ResourcesCount: 3,
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
