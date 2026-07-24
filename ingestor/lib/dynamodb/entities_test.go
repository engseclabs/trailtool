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

func TestMergeResourceAccessItemsKeepsResourceAccountsDistinct(t *testing.T) {
	first := types.ResourceAccessItem{
		Resource:          "lambda:function:shared-function",
		ResourceAccountID: "111111111111",
		Service:           "lambda.amazonaws.com",
		EventName:         "Invoke",
		Count:             1,
	}
	second := first
	second.ResourceAccountID = "222222222222"

	got := MergeResourceAccessItems([]types.ResourceAccessItem{first}, []types.ResourceAccessItem{second})
	if len(got) != 2 {
		t.Fatalf("merged accesses = %#v, want two account-qualified entries", got)
	}
	if got[0].ResourceAccountID != "111111111111" || got[1].ResourceAccountID != "222222222222" {
		t.Fatalf("resource accounts = %#v", got)
	}
}

func TestMergeRoleAndResourceDoNotAddDistinctCounts(t *testing.T) {
	role := MergeRoleAggregated(
		&types.DynamoDBRole{
			ARN:           "arn:aws:iam::111111111111:role/reader",
			PeopleCount:   4,
			SessionsCount: 3,
			AccountsCount: 1,
		},
		&types.DynamoDBRole{
			ARN:           "arn:aws:iam::111111111111:role/reader",
			PeopleCount:   2,
			SessionsCount: 5,
			AccountsCount: 1,
		},
	)
	if role.PeopleCount != 4 || role.SessionsCount != 5 || role.AccountsCount != 1 {
		t.Fatalf("role relationship counts = %d/%d/%d, want 4/5/1",
			role.PeopleCount, role.SessionsCount, role.AccountsCount)
	}

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
			PersonKey:           "email#alex@example.com",
			DeniedEventCount:    1,
			TopDeniedEventNames: map[string]int{"s3.amazonaws.com:GetObject": 1},
		},
		&types.DynamoDBPerson{
			PersonKey:           "email#alex@example.com",
			DeniedEventCount:    2,
			TopDeniedEventNames: map[string]int{"s3.amazonaws.com:GetObject": 2},
		},
	)
	if got.DeniedEventCount != 3 || got.TopDeniedEventNames["s3.amazonaws.com:GetObject"] != 3 {
		t.Fatalf("merged person denied activity = %+v", got)
	}
}
