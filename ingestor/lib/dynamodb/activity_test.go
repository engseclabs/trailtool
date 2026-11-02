package dynamodb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/internal/ddbfake"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const (
	testRoles    = "trailtool-roles"
	testServices = "trailtool-services"
	testRoleARN  = "arn:aws:iam::111111111111:role/app"
)

func newNounFake() *ddbfake.Store {
	return ddbfake.New(map[string][2]string{
		testRoles:    {"customerId", RoleSortAttr},
		testServices: {"customerId", ServiceSortAttr},
	})
}

func nounKey(sortAttr, partition, sk string) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{"customerId": str(partition), sortAttr: str(sk)}
}

func numAttr(t *testing.T, item map[string]ddbtypes.AttributeValue, attr string) int {
	t.Helper()
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

// readCount reads one activity counter.
func readCount(t *testing.T, store *ddbfake.Store, table, sortAttr, id, sk, attr string) int {
	t.Helper()
	return numAttr(t, store.Get(table, nounKey(sortAttr, ActivityPartition("default", id), sk)), attr)
}

func roleBatch(first, last, resource string) *types.DynamoDBRole {
	return &types.DynamoDBRole{
		CustomerID:          "default",
		ARN:                 testRoleARN,
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
			Resource: "s3:bucket:locked", ResourceAccountID: "111111111111",
			Service: "s3.amazonaws.com", EventName: "PutObject", Count: 1,
			PolicyARN: "arn:aws:organizations::111111111111:policy/scp", PolicyType: "SCP",
			ErrorMessage: "denied by scp",
		}},
	}
}

func storedRole(t *testing.T, store *ddbfake.Store) types.DynamoDBRole {
	t.Helper()
	var role types.DynamoDBRole
	if err := attributevalue.UnmarshalMap(store.Get(testRoles, nounKey(RoleSortAttr, "default", testRoleARN)), &role); err != nil {
		t.Fatal(err)
	}
	return role
}

func seedLegacyRole(t *testing.T, store *ddbfake.Store) {
	t.Helper()
	legacy := roleBatch("2026-01-01T10:00:00Z", "2026-01-01T11:00:00Z", "s3:bucket:old")
	legacy.TotalEvents = 40
	legacy.TopEventNames = map[string]int{"s3.amazonaws.com:GetObject": 40}
	legacy.ServicesCount = map[string]int{"s3.amazonaws.com": 40}
	legacy.ResourceAccesses[0].Count = 40
	legacy.ResourcesUsed = []string{"s3:bucket:old"}
	legacy.ResourcesCount = map[string]int{"s3:bucket:old": 40}
	item, err := attributevalue.MarshalMap(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Seed(testRoles, item); err != nil {
		t.Fatal(err)
	}
}

func getObjectCount(t *testing.T, store *ddbfake.Store) int {
	return readCount(t, store, testRoles, RoleSortAttr, testRoleARN, "evt#s3.amazonaws.com", "c:s3.amazonaws.com:GetObject")
}

func TestWriteRoleKeepsTheMainItemSmall(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	roleKey := nounKey(RoleSortAttr, "default", testRoleARN)
	var firstSize int
	for i := 0; i < 300; i++ {
		ts := fmt.Sprintf("2026-01-01T%02d:%02d:00Z", i/60, i%60)
		if err := WriteRoleToDynamoDB(ctx, store, testRoles, roleBatch(ts, ts, fmt.Sprintf("s3:bucket:b%d", i))); err != nil {
			t.Fatal(err)
		}
		size := ddbfake.ItemSize(store.Get(testRoles, roleKey))
		if i == 0 {
			firstSize = size
		}
		if size > firstSize+8 {
			t.Fatalf("role item grew from %d to %d bytes after %d batches", firstSize, size, i+1)
		}
	}
	role := storedRole(t, store)
	if role.TotalEvents != 600 || role.TotalDeniedEvents != 300 || role.Name != "app" {
		t.Fatalf("role = %+v", role)
	}
	if role.FirstSeen != "2026-01-01T00:00:00Z" || role.LastSeen != "2026-01-01T04:59:00Z" {
		t.Fatalf("bounds = %s..%s", role.FirstSeen, role.LastSeen)
	}
	if got := getObjectCount(t, store); got != 600 {
		t.Fatalf("GetObject = %d", got)
	}
	evt := store.Get(testRoles, nounKey(RoleSortAttr, ActivityPartition("default", testRoleARN), "evt#s3.amazonaws.com"))
	if numAttr(t, evt, "d:s3.amazonaws.com:PutObject") != 300 || numAttr(t, evt, ServiceCountAttr) != 600 {
		t.Fatalf("event item = %v", evt)
	}
	// main + one per-source event item + 300 resources + one denied access
	if n := len(store.Items(testRoles)); n != 1+1+300+1 {
		t.Fatalf("role table items = %d", n)
	}
	for _, item := range store.Items(testRoles) {
		if size := ddbfake.ItemSize(item); size > 1024 {
			t.Fatalf("item of %d bytes: %v", size, item)
		}
	}
}

func TestWriteRoleBoundsNeverRegress(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	for _, b := range [][2]string{
		{"2026-01-01T10:00:00Z", "2026-01-01T11:00:00Z"},
		{"2026-01-01T08:00:00Z", "2026-01-01T09:00:00Z"}, // older file, delivered late
		{"2026-01-01T11:30:00Z", "2026-01-01T12:00:00Z"},
	} {
		if err := WriteRoleToDynamoDB(ctx, store, testRoles, roleBatch(b[0], b[1], "s3:bucket:x")); err != nil {
			t.Fatal(err)
		}
	}
	role := storedRole(t, store)
	if role.FirstSeen != "2026-01-01T08:00:00Z" || role.LastSeen != "2026-01-01T12:00:00Z" || role.TotalEvents != 6 {
		t.Fatalf("role = %s..%s total %d", role.FirstSeen, role.LastSeen, role.TotalEvents)
	}
}

// A replica that has not seen the item must not make the writer treat it as
// new and keep the stored first_seen through if_not_exists.
func TestStaleReadCannotDropTheEarliestObservation(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	if err := WriteRoleToDynamoDB(ctx, store, testRoles, roleBatch("2026-01-01T10:00:00Z", "2026-01-01T11:00:00Z", "s3:bucket:x")); err != nil {
		t.Fatal(err)
	}
	store.StaleGet = func(*dynamodb.GetItemInput) (ddbfake.Item, bool) { return nil, true }
	if err := WriteRoleToDynamoDB(ctx, store, testRoles, roleBatch("2026-01-01T08:00:00Z", "2026-01-01T12:00:00Z", "s3:bucket:x")); err != nil {
		t.Fatal(err)
	}
	role := storedRole(t, store)
	if role.FirstSeen != "2026-01-01T08:00:00Z" || role.LastSeen != "2026-01-01T12:00:00Z" {
		t.Fatalf("bounds = %s..%s, want 08:00..12:00", role.FirstSeen, role.LastSeen)
	}
	if role.TotalEvents != 4 {
		t.Fatalf("total_events = %d", role.TotalEvents)
	}
}

// Pre-activity items are not migrated: their first write removes the inline
// maps and keeps the totals and bounds.
func TestWriteRoleDropsLegacyInlineAttributes(t *testing.T) {
	store := newNounFake()
	seedLegacyRole(t, store)
	legacySize := ddbfake.ItemSize(store.Get(testRoles, nounKey(RoleSortAttr, "default", testRoleARN)))
	if err := WriteRoleToDynamoDB(context.Background(), store, testRoles,
		roleBatch("2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z", "s3:bucket:old")); err != nil {
		t.Fatal(err)
	}
	main := store.Get(testRoles, nounKey(RoleSortAttr, "default", testRoleARN))
	for _, attr := range LegacyRoleAttrs {
		if _, ok := main[attr]; ok {
			t.Fatalf("legacy attribute %s survived the first write", attr)
		}
	}
	if size := ddbfake.ItemSize(main); size >= legacySize {
		t.Fatalf("item did not shrink: %d -> %d bytes", legacySize, size)
	}
	role := storedRole(t, store)
	if role.TotalEvents != 42 || role.FirstSeen != "2026-01-01T10:00:00Z" || role.LastSeen != "2026-01-02T00:00:00Z" {
		t.Fatalf("role = %+v", role)
	}
	// Only post-upgrade activity is broken down.
	if got := getObjectCount(t, store); got != 2 {
		t.Fatalf("GetObject = %d, want 2", got)
	}
}

func TestWriteServiceDropsLegacyInlineAttributes(t *testing.T) {
	ctx := context.Background()
	store := newNounFake()
	legacy, err := attributevalue.MarshalMap(&types.DynamoDBService{
		CustomerID: "default", EventSource: "s3.amazonaws.com", DisplayName: "S3", TotalEvents: 10,
		RolesUsing: []string{"r1", "r2"}, ResourcesUsed: []string{"b1"},
		TopEventNames: map[string]int{"GetObject": 10}, FirstSeen: "2026-01-01T00:00:00Z", LastSeen: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Seed(testServices, legacy); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := WriteServiceToDynamoDB(ctx, store, testServices, &types.DynamoDBService{
			CustomerID: "default", EventSource: "s3.amazonaws.com", DisplayName: "S3", TotalEvents: 2,
			RolesUsing: []string{"r3"}, TopEventNames: map[string]int{"GetObject": 2},
			TopDeniedEventNames: map[string]int{"PutObject": 1},
			FirstSeen:           "2026-01-02T00:00:00Z", LastSeen: "2026-01-02T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}
	main := store.Get(testServices, nounKey(ServiceSortAttr, "default", "s3.amazonaws.com"))
	for _, attr := range LegacyServiceAttrs {
		if _, ok := main[attr]; ok {
			t.Fatalf("service still stores %s", attr)
		}
	}
	var svc types.DynamoDBService
	if err := attributevalue.UnmarshalMap(main, &svc); err != nil {
		t.Fatal(err)
	}
	if svc.TotalEvents != 16 || svc.DisplayName != "S3" || svc.LastSeen != "2026-01-02T00:00:00Z" {
		t.Fatalf("service = %+v", svc)
	}
	if got := readCount(t, store, testServices, ServiceSortAttr, "s3.amazonaws.com", "evt#GetObject", "c:GetObject"); got != 6 {
		t.Fatalf("GetObject = %d", got)
	}
	if got := readCount(t, store, testServices, ServiceSortAttr, "s3.amazonaws.com", "evt#PutObject", "d:PutObject"); got != 3 {
		t.Fatalf("PutObject denied = %d", got)
	}
}

func TestLargeCounterSetsAreSplit(t *testing.T) {
	// 350 event names under one source in one batch: more counters than one
	// update expression can carry.
	store := newNounFake()
	batch := roleBatch("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "s3:bucket:x")
	for i := 0; i < 350; i++ {
		batch.TopEventNames[fmt.Sprintf("ec2.amazonaws.com:DescribeThing%03d", i)] = i + 1
	}
	var longest int
	store.FailUpdate = func(in *dynamodb.UpdateItemInput) error {
		longest = max(longest, len(aws.ToString(in.UpdateExpression)))
		return nil
	}
	if err := WriteRoleToDynamoDB(context.Background(), store, testRoles, batch); err != nil {
		t.Fatal(err)
	}
	if longest > 4096 {
		t.Fatalf("longest update expression is %d bytes", longest)
	}
	if got := readCount(t, store, testRoles, RoleSortAttr, testRoleARN, "evt#ec2.amazonaws.com", "c:ec2.amazonaws.com:DescribeThing349"); got != 350 {
		t.Fatalf("DescribeThing349 = %d", got)
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
