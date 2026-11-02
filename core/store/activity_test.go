package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/core/models"
)

func n(v int) types.AttributeValue    { return &types.AttributeValueMemberN{Value: fmt.Sprint(v)} }
func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func TestActivityPartitionMatchesIngestorLayout(t *testing.T) {
	if got := ActivityPartition("default", "s3.amazonaws.com"); got != "default#act#s3.amazonaws.com" {
		t.Fatalf("partition = %q", got)
	}
	// ingestor/lib/dynamodb asserts the same value.
	if got := ActivityPartition("default", strings.Repeat("x", 4000)); got != "default#act#sha256:91c9568c40c8d8d1f7a1bd029d124994" {
		t.Fatalf("hashed partition = %q", got)
	}
}

func TestParseActivityItemSeparatesBatchAndMigratedCounters(t *testing.T) {
	it, err := parseActivityItem(map[string]types.AttributeValue{
		"kind": s("evt"), "name": s("s3.amazonaws.com"),
		"c:s3.amazonaws.com:GetObject":  n(2),
		"lc:s3.amazonaws.com:GetObject": n(40),
		"d:s3.amazonaws.com:PutObject":  n(1),
		"service_count":                 n(2),
		"legacy_service_count":          n(40),
	})
	if err != nil {
		t.Fatal(err)
	}
	if it.Allowed["s3.amazonaws.com:GetObject"] != 2 || it.LegacyAllowed["s3.amazonaws.com:GetObject"] != 40 ||
		it.Denied["s3.amazonaws.com:PutObject"] != 1 || it.ServiceCount != 2 || it.LegacyServiceCount != 40 {
		t.Fatalf("item = %+v", it)
	}
}

func migratedItems() []ActivityItem {
	return []ActivityItem{
		{Kind: activityEvent, Name: "s3.amazonaws.com", ServiceCount: 2, LegacyServiceCount: 40,
			Allowed: map[string]int{"s3.amazonaws.com:GetObject": 2}, LegacyAllowed: map[string]int{"s3.amazonaws.com:GetObject": 40}},
		{Kind: activityResourceAccess, Resource: "s3:bucket:a", ResourceAccountID: "111111111111", Service: "s3.amazonaws.com",
			Allowed: map[string]int{"GetObject": 2}, LegacyAllowed: map[string]int{"GetObject": 40}},
		{Kind: activityDeniedResourceAccess, Resource: "kms:key:k", Service: "kms.amazonaws.com", EventName: "Decrypt",
			Count: 1, LegacyCount: 3, PolicyARN: "p", PolicyType: "SCP"},
		{Kind: activityDeniedEventAccess, Service: "iam.amazonaws.com", EventName: "ListRoles", Count: 1, ErrorMessage: "denied"},
	}
}

func TestApplyRoleActivityUsesMigratedCopiesOnceInlineMapsAreGone(t *testing.T) {
	role := &models.Role{}
	ApplyRoleActivity(role, migratedItems())
	if role.TopEventNames["s3.amazonaws.com:GetObject"] != 42 || role.ServicesCount["s3.amazonaws.com"] != 42 {
		t.Fatalf("events = %v services = %v", role.TopEventNames, role.ServicesCount)
	}
	if len(role.ResourceAccesses) != 1 || role.ResourceAccesses[0].Count != 42 || role.ResourcesCount["s3:bucket:a"] != 42 {
		t.Fatalf("accesses = %+v", role.ResourceAccesses)
	}
	if role.DeniedResourceAccesses[0].Count != 4 || role.DeniedResourceAccesses[0].PolicyType != "SCP" {
		t.Fatalf("denied = %+v", role.DeniedResourceAccesses)
	}
	if strings.Join(role.ServicesUsed, ",") != "s3.amazonaws.com" || strings.Join(role.ResourcesUsed, ",") != "s3:bucket:a" {
		t.Fatalf("used = %v %v", role.ServicesUsed, role.ResourcesUsed)
	}
}

// While the main item still holds its inline maps, the migrated copies are
// ignored: counting both would double the history.
func TestApplyRoleActivityIgnoresCopiesWhileInlineMapsRemain(t *testing.T) {
	role := &models.Role{
		LegacyInline:  true,
		TopEventNames: map[string]int{"s3.amazonaws.com:GetObject": 40},
		ServicesCount: map[string]int{"s3.amazonaws.com": 40},
		ResourceAccesses: []models.ResourceAccessItem{{
			Resource: "s3:bucket:a", ResourceAccountID: "111111111111", Service: "s3.amazonaws.com", EventName: "GetObject", Count: 40,
		}},
		DeniedResourceAccesses: []models.ResourceAccessItem{{
			Resource: "kms:key:k", Service: "kms.amazonaws.com", EventName: "Decrypt", Count: 3, PolicyARN: "p",
		}},
	}
	ApplyRoleActivity(role, migratedItems())
	if role.TopEventNames["s3.amazonaws.com:GetObject"] != 42 || role.ServicesCount["s3.amazonaws.com"] != 42 {
		t.Fatalf("events = %v services = %v", role.TopEventNames, role.ServicesCount)
	}
	if len(role.ResourceAccesses) != 1 || role.ResourceAccesses[0].Count != 42 {
		t.Fatalf("accesses = %+v", role.ResourceAccesses)
	}
	if role.DeniedResourceAccesses[0].Count != 4 || role.DeniedResourceAccesses[0].PolicyType != "SCP" {
		t.Fatalf("denied = %+v", role.DeniedResourceAccesses)
	}
}

func TestApplyServiceActivity(t *testing.T) {
	items := []ActivityItem{{Kind: activityEvent, Name: "GetObject",
		Allowed: map[string]int{"GetObject": 2}, LegacyAllowed: map[string]int{"GetObject": 10},
		Denied: map[string]int{"GetObject": 1}}}
	migrated := &models.Service{}
	ApplyServiceActivity(migrated, items)
	inline := &models.Service{LegacyInline: true, TopEventNames: map[string]int{"GetObject": 10}}
	ApplyServiceActivity(inline, items)
	for _, svc := range []*models.Service{migrated, inline} {
		if svc.TopEventNames["GetObject"] != 12 || svc.TopDeniedEventNames["GetObject"] != 1 {
			t.Fatalf("service = %+v", svc)
		}
	}
}

func TestApplyRoleActivityScalesLinearly(t *testing.T) {
	items := make([]ActivityItem, 0, 50000)
	for i := 0; i < 50000; i++ {
		items = append(items, ActivityItem{Kind: activityResourceAccess, Resource: fmt.Sprintf("s3:bucket:%d", i),
			Service: "s3.amazonaws.com", Allowed: map[string]int{"GetObject": 1, "PutObject": 1}})
	}
	start := time.Now()
	role := &models.Role{}
	ApplyRoleActivity(role, items)
	if len(role.ResourceAccesses) != 100000 {
		t.Fatalf("accesses = %d", len(role.ResourceAccesses))
	}
	// The previous slice scan took minutes here; a map takes well under a second.
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("100k accesses took %s", d)
	}
}
