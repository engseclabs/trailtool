package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"

	"github.com/engseclabs/trailtool/ingestor/lib/dynamodb/ddbfake"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const (
	testRoles     = "trailtool-roles"
	testServices  = "trailtool-services"
	testResources = "trailtool-resources"
	testAccounts  = "trailtool-accounts"
)

func newNounFake() *ddbfake.Store {
	return ddbfake.New(map[string]ddbfake.KeySchema{
		testRoles:     {Hash: "customerId", Range: RoleSortAttr},
		testServices:  {Hash: "customerId", Range: ServiceSortAttr},
		testResources: {Hash: "customerId", Range: ResourceSortAttr},
		testAccounts:  {Hash: "customerId", Range: AccountSortAttr},
	})
}

func key(sortAttr, partition, sk string) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{
		"customerId": &ddbtypes.AttributeValueMemberS{Value: partition},
		sortAttr:     &ddbtypes.AttributeValueMemberS{Value: sk},
	}
}

func activity(t *testing.T, store *ddbfake.Store, table, sortAttr, partition, sk string) types.DynamoDBActivity {
	t.Helper()
	item := store.Get(table, key(sortAttr, partition, sk))
	if item == nil {
		t.Fatalf("activity %s/%s missing", partition, sk)
	}
	var a types.DynamoDBActivity
	if err := attributevalue.UnmarshalMap(item, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func counter(t *testing.T, store *ddbfake.Store, table, sortAttr, partition, sk, attr string) int {
	t.Helper()
	item := store.Get(table, key(sortAttr, partition, sk))
	if item == nil {
		t.Fatalf("activity %s/%s missing", partition, sk)
	}
	n, ok := item[attr].(*ddbtypes.AttributeValueMemberN)
	if !ok {
		return 0
	}
	v, err := strconv.Atoi(n.Value)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func roleBatch(first, last string, resource string) *types.DynamoDBRole {
	return &types.DynamoDBRole{
		CustomerID:          "default",
		ARN:                 "arn:aws:iam::111111111111:role/app",
		Name:                "app",
		AccountID:           "111111111111",
		FirstSeen:           first,
		LastSeen:            last,
		TotalEvents:         2,
		TotalDeniedEvents:   1,
		ServicesCount:       map[string]int{"s3.amazonaws.com": 2},
		TopEventNames:       map[string]int{"s3.amazonaws.com:GetObject": 2},
		TopDeniedEventNames: map[string]int{"s3.amazonaws.com:PutObject": 1},
		ResourceAccesses: []types.ResourceAccessItem{{
			Resource: resource, ResourceAccountID: "111111111111",
			Service: "s3.amazonaws.com", EventName: "GetObject", Count: 2,
		}},
		DeniedResourceAccesses: []types.ResourceAccessItem{{
			Resource: "s3:bucket/locked", ResourceAccountID: "111111111111",
			Service: "s3.amazonaws.com", EventName: "PutObject", Count: 1,
			PolicyARN: "arn:aws:organizations::111111111111:policy/scp", PolicyType: "SCP",
			ErrorMessage: "denied by scp",
		}},
	}
}

func TestWriteRoleAddsCountersWithoutGrowingTheMainItem(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	roleKey := key(RoleSortAttr, "default", "arn:aws:iam::111111111111:role/app")

	var firstSize int
	for i := 0; i < 500; i++ {
		ts := fmt.Sprintf("2026-01-01T%02d:%02d:00Z", i/60%24, i%60)
		if err := WriteRoleToDynamoDB(ctx, store, testRoles, roleBatch(ts, ts, fmt.Sprintf("s3:bucket/b%d", i))); err != nil {
			t.Fatal(err)
		}
		size := ddbfake.ItemSize(store.Get(testRoles, roleKey))
		if i == 0 {
			firstSize = size
		}
		if size > firstSize+16 {
			t.Fatalf("role item grew from %d to %d bytes after %d batches", firstSize, size, i+1)
		}
	}

	var role types.DynamoDBRole
	if err := attributevalue.UnmarshalMap(store.Get(testRoles, roleKey), &role); err != nil {
		t.Fatal(err)
	}
	if role.TotalEvents != 1000 || role.TotalDeniedEvents != 500 {
		t.Fatalf("totals = %d/%d", role.TotalEvents, role.TotalDeniedEvents)
	}
	if role.FirstSeen != "2026-01-01T00:00:00Z" || role.LastSeen != "2026-01-01T08:19:00Z" {
		t.Fatalf("bounds = %s..%s", role.FirstSeen, role.LastSeen)
	}
	if role.Name != "app" || role.AccountID != "111111111111" {
		t.Fatalf("identity = %+v", role)
	}

	partition := ActivityPartition("default", role.ARN)
	evt := func(attr string) int {
		return counter(t, store, testRoles, RoleSortAttr, partition, "evt#s3.amazonaws.com", attr)
	}
	if got := evt("c:s3.amazonaws.com:GetObject"); got != 1000 {
		t.Fatalf("GetObject count = %d", got)
	}
	if got := evt("d:s3.amazonaws.com:PutObject"); got != 500 {
		t.Fatalf("PutObject denied = %d", got)
	}
	if got := evt("c:s3.amazonaws.com:PutObject"); got != 0 {
		t.Fatalf("PutObject allowed = %d", got)
	}
	if got := evt(ServiceCountAttr); got != 1000 {
		t.Fatalf("service count = %d", got)
	}

	// Main item, one item per service, one per resource, one denied access.
	stats := store.Stats()[testRoles]
	if stats.Items != 1+1+500+1 {
		t.Fatalf("role table items = %d", stats.Items)
	}
	if stats.MaxItemSize > 1024 {
		t.Fatalf("largest role-table item is %d bytes", stats.MaxItemSize)
	}
}

func TestLegacyRoleWriteHitsTheItemLimit(t *testing.T) {
	// The before picture: the read-merge-put path grows the item with every
	// distinct resource until DynamoDB rejects it.
	ctx := context.Background()
	store := newNounFake()
	var err error
	for i := 0; i < 5000 && err == nil; i++ {
		err = LegacyWriteRoleToDynamoDB(ctx, store, testRoles, roleBatch("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
			fmt.Sprintf("s3:bucket/data-lake/%s/object-%06d.parquet", strings.Repeat("partition=x/", 40), i)))
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || !strings.Contains(apiErr.ErrorMessage(), "Item size has exceeded") {
		t.Fatalf("legacy write error = %v, want item-size ValidationException", err)
	}
}

func TestWriteRoleLastSeenNeverMovesBackward(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	roleKey := key(RoleSortAttr, "default", "arn:aws:iam::111111111111:role/app")
	steps := []struct{ first, last string }{
		{"2026-01-01T10:00:00Z", "2026-01-01T11:00:00Z"},
		{"2026-01-01T08:00:00Z", "2026-01-01T09:00:00Z"}, // older file, delivered late
		{"2026-01-01T11:30:00Z", "2026-01-01T12:00:00Z"},
	}
	for _, s := range steps {
		if err := WriteRoleToDynamoDB(ctx, store, testRoles, roleBatch(s.first, s.last, "s3:bucket/x")); err != nil {
			t.Fatal(err)
		}
	}
	var role types.DynamoDBRole
	if err := attributevalue.UnmarshalMap(store.Get(testRoles, roleKey), &role); err != nil {
		t.Fatal(err)
	}
	if role.FirstSeen != "2026-01-01T08:00:00Z" || role.LastSeen != "2026-01-01T12:00:00Z" {
		t.Fatalf("bounds = %s..%s", role.FirstSeen, role.LastSeen)
	}
	if role.TotalEvents != 6 {
		t.Fatalf("late batch lost its counts: total_events = %d", role.TotalEvents)
	}
}

func TestWriteRoleMigratesLegacyAttributesOnce(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	legacy := roleBatch("2025-12-01T00:00:00Z", "2025-12-02T00:00:00Z", "s3:bucket/old")
	legacy.TotalEvents = 40
	legacy.TopEventNames = map[string]int{"s3.amazonaws.com:GetObject": 30, "s3.amazonaws.com:ListBucket": 10}
	legacy.ServicesCount = map[string]int{"s3.amazonaws.com": 40}
	legacy.ResourcesUsed = []string{"s3:bucket/old"}
	legacy.ResourcesCount = map[string]int{"s3:bucket/old": 2}
	legacy.PeopleCount = 3
	item, err := attributevalue.MarshalMap(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Seed(testRoles, item); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		if err := WriteRoleToDynamoDB(ctx, store, testRoles, roleBatch("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "s3:bucket/old")); err != nil {
			t.Fatal(err)
		}
	}

	main := store.Get(testRoles, key(RoleSortAttr, "default", legacy.ARN))
	for _, attr := range legacyRoleAttrs {
		if _, ok := main[attr]; ok {
			t.Fatalf("legacy attribute %s survived", attr)
		}
	}
	var role types.DynamoDBRole
	if err := attributevalue.UnmarshalMap(main, &role); err != nil {
		t.Fatal(err)
	}
	if role.TotalEvents != 44 || role.FirstSeen != "2025-12-01T00:00:00Z" || role.LastSeen != "2026-01-01T00:00:00Z" || role.PeopleCount != 3 {
		t.Fatalf("migrated role = %+v", role)
	}

	partition := ActivityPartition("default", legacy.ARN)
	evt := func(attr string) int {
		return counter(t, store, testRoles, RoleSortAttr, partition, "evt#s3.amazonaws.com", attr)
	}
	if got := evt("c:s3.amazonaws.com:GetObject"); got != 34 {
		t.Fatalf("GetObject = %d, want 30 legacy + 2×2", got)
	}
	if got := evt("c:s3.amazonaws.com:ListBucket"); got != 10 {
		t.Fatalf("ListBucket = %d", got)
	}
	if got := evt(ServiceCountAttr); got != 44 {
		t.Fatalf("svc = %d", got)
	}
	raSK := "ra#" + digest("s3.amazonaws.com", "111111111111", "s3:bucket/old")
	ra := activity(t, store, testRoles, RoleSortAttr, partition, raSK)
	if got := counter(t, store, testRoles, RoleSortAttr, partition, raSK, "c:GetObject"); got != 6 || ra.Resource != "s3:bucket/old" {
		t.Fatalf("resource access = %+v, count %d", ra, got)
	}
	dra := activity(t, store, testRoles, RoleSortAttr, partition,
		"dra#"+digest("s3.amazonaws.com", "PutObject", "111111111111", "s3:bucket/locked", "arn:aws:organizations::111111111111:policy/scp"))
	if dra.Count != 3 || dra.PolicyType != "SCP" || dra.ErrorMessage != "denied by scp" {
		t.Fatalf("denied access = %+v", dra)
	}
}

func TestWriteResourceTracksClickOpsAndUpgradesUnknownType(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	batch := func(typ string, ref string) *types.DynamoDBResource {
		return &types.DynamoDBResource{
			CustomerID: "default", ResourceKey: "111111111111|s3:bucket/x", Identifier: "s3:bucket/x",
			Type: typ, AccountID: "111111111111", FirstSeen: "2026-01-01T00:00:00Z", LastSeen: "2026-01-01T00:00:00Z",
			TotalEvents: 1, TopEventNames: map[string]int{"PutBucketPolicy": 1},
			ClickOpsAccesses: []types.ClickOpsAccess{{
				SessionRef: ref, PersonKey: "email#a@example.com", EventName: "PutBucketPolicy",
				AccessTime: "2026-01-01T00:00:00Z", EventCount: 1, AccountID: "111111111111",
			}},
		}
	}
	for _, b := range []*types.DynamoDBResource{batch("unknown", "p|s1"), batch("s3:bucket", "p|s1"), batch("s3:bucket", "p|s2")} {
		if err := WriteResourceToDynamoDB(ctx, store, testResources, b); err != nil {
			t.Fatal(err)
		}
	}
	var r types.DynamoDBResource
	if err := attributevalue.UnmarshalMap(store.Get(testResources, key(ResourceSortAttr, "default", "111111111111|s3:bucket/x")), &r); err != nil {
		t.Fatal(err)
	}
	if r.Type != "s3:bucket" || r.ClickOpsCount != 3 || r.TotalEvents != 3 || len(r.ClickOpsAccesses) != 0 {
		t.Fatalf("resource = %+v", r)
	}
	if got := counter(t, store, testResources, ResourceSortAttr, "default", "111111111111|s3:bucket/x", "c:PutBucketPolicy"); got != 3 {
		t.Fatalf("inline PutBucketPolicy = %d", got)
	}
	partition := ActivityPartition("default", "111111111111|s3:bucket/x")
	co := activity(t, store, testResources, ResourceSortAttr, partition, "co#"+digest("p|s1", "PutBucketPolicy"))
	if co.Count != 2 || co.PersonKey != "email#a@example.com" || co.ResourceAccountID != "111111111111" {
		t.Fatalf("clickops = %+v", co)
	}
}

func TestWriteServiceAndAccountUseActivityItems(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	for i := 0; i < 3; i++ {
		if err := WriteServiceToDynamoDB(ctx, store, testServices, &types.DynamoDBService{
			CustomerID: "default", EventSource: "s3.amazonaws.com", DisplayName: "S3", Category: "storage",
			TotalEvents: 2, RolesUsing: []string{fmt.Sprintf("role-%d", i)}, ResourcesUsed: []string{fmt.Sprintf("r-%d", i)},
			TopEventNames: map[string]int{"GetObject": 2}, FirstSeen: "2026-01-01T00:00:00Z", LastSeen: "2026-01-01T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
		if err := WriteAccountToDynamoDB(ctx, store, testAccounts, &types.DynamoDBAccount{
			CustomerID: "default", AccountID: "111111111111", EventsCount: 2, ClickOpsCount: 1,
			TopEventNames: map[string]int{"s3.amazonaws.com:GetObject": 2}, FirstSeen: "2026-01-01T00:00:00Z", LastSeen: "2026-01-01T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}
	svcItem := store.Get(testServices, key(ServiceSortAttr, "default", "s3.amazonaws.com"))
	if _, ok := svcItem["roles_using"]; ok {
		t.Fatal("service item still stores roles_using")
	}
	var svc types.DynamoDBService
	if err := attributevalue.UnmarshalMap(svcItem, &svc); err != nil {
		t.Fatal(err)
	}
	if svc.TotalEvents != 6 || svc.DisplayName != "S3" {
		t.Fatalf("service = %+v", svc)
	}
	if got := counter(t, store, testServices, ServiceSortAttr, ActivityPartition("default", "s3.amazonaws.com"), "evt#GetObject", "c:GetObject"); got != 6 {
		t.Fatalf("service GetObject = %d", got)
	}
	var account types.DynamoDBAccount
	if err := attributevalue.UnmarshalMap(store.Get(testAccounts, key(AccountSortAttr, "default", "111111111111")), &account); err != nil {
		t.Fatal(err)
	}
	if account.EventsCount != 6 || account.ClickOpsCount != 3 {
		t.Fatalf("account = %+v", account)
	}
	if got := counter(t, store, testAccounts, AccountSortAttr, ActivityPartition("default", "111111111111"), "evt#s3.amazonaws.com", "c:s3.amazonaws.com:GetObject"); got != 6 {
		t.Fatalf("account GetObject = %d", got)
	}
}

func TestActivityKeysStayWithinDynamoDBLimits(t *testing.T) {
	long := strings.Repeat("x", 4000)
	// core/store.ActivityPartition asserts the same value.
	if p := ActivityPartition("default", long); p != "default#act#sha256:91c9568c40c8d8d1f7a1bd029d124994" {
		t.Fatalf("partition = %q", p)
	}
	if p := ActivityPartition("default", "s3.amazonaws.com"); p != "default#act#s3.amazonaws.com" {
		t.Fatalf("partition = %q", p)
	}
	if sk := ActivitySortKey(ActivityEvent, long); len(sk) > maxSortKeyBytes || !strings.HasPrefix(sk, "evt#sha256:") {
		t.Fatalf("sort key = %q", sk)
	}
}

func TestLegacyMigrationSplitsLargeCounterSets(t *testing.T) {
	// 350 event names on one account and one resource: more counters than
	// one update expression can carry.
	ctx := context.Background()
	store := newNounFake()
	events := map[string]int{}
	resourceEvents := map[string]int{}
	for i := 0; i < 350; i++ {
		events[fmt.Sprintf("ec2.amazonaws.com:DescribeThing%03d", i)] = i + 1
		resourceEvents[fmt.Sprintf("DescribeThing%03d", i)] = i + 1
	}
	account, err := attributevalue.MarshalMap(&types.DynamoDBAccount{CustomerID: "default", AccountID: "111111111111", TopEventNames: events})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := attributevalue.MarshalMap(&types.DynamoDBResource{CustomerID: "default", ResourceKey: "r", TopEventNames: resourceEvents})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Seed(testAccounts, account); err != nil {
		t.Fatal(err)
	}
	if err := store.Seed(testResources, resource); err != nil {
		t.Fatal(err)
	}
	if err := WriteAccountToDynamoDB(ctx, store, testAccounts, &types.DynamoDBAccount{CustomerID: "default", AccountID: "111111111111", EventsCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := WriteResourceToDynamoDB(ctx, store, testResources, &types.DynamoDBResource{CustomerID: "default", ResourceKey: "r", TotalEvents: 1}); err != nil {
		t.Fatal(err)
	}
	if got := counter(t, store, testAccounts, AccountSortAttr, ActivityPartition("default", "111111111111"), "evt#ec2.amazonaws.com", "c:ec2.amazonaws.com:DescribeThing349"); got != 350 {
		t.Fatalf("account counter = %d", got)
	}
	if got := counter(t, store, testResources, ResourceSortAttr, "default", "r", "c:DescribeThing000"); got != 1 {
		t.Fatalf("resource counter = %d", got)
	}
	if got := counter(t, store, testResources, ResourceSortAttr, "default", "r", "c:DescribeThing349"); got != 350 {
		t.Fatalf("resource counter = %d", got)
	}
}
