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

func TestParseActivityItemReadsCounters(t *testing.T) {
	it, err := parseActivityItem(map[string]types.AttributeValue{
		"kind": s("evt"), "name": s("s3.amazonaws.com"),
		"c:s3.amazonaws.com:GetObject": n(2),
		"d:s3.amazonaws.com:PutObject": n(1),
		"service_count":                n(3),
		"total_events":                 n(9),
	})
	if err != nil {
		t.Fatal(err)
	}
	if it.Allowed["s3.amazonaws.com:GetObject"] != 2 || it.Denied["s3.amazonaws.com:PutObject"] != 1 ||
		it.ServiceCount != 3 || len(it.Allowed) != 1 {
		t.Fatalf("item = %+v", it)
	}
}

func roleItems() []ActivityItem {
	return []ActivityItem{
		{Kind: activityEvent, Name: "s3.amazonaws.com", ServiceCount: 2,
			Allowed: map[string]int{"s3.amazonaws.com:GetObject": 2}},
		{Kind: activityEvent, Name: "kms.amazonaws.com", ServiceCount: 1,
			Allowed: map[string]int{"kms.amazonaws.com:Decrypt": 1}, Denied: map[string]int{"kms.amazonaws.com:Decrypt": 3}},
		{Kind: activityResourceAccess, Resource: "s3:bucket:a", ResourceAccountID: "111111111111", Service: "s3.amazonaws.com",
			Allowed: map[string]int{"GetObject": 2}},
		{Kind: activityDeniedResourceAccess, Resource: "kms:key:k", Service: "kms.amazonaws.com", EventName: "Decrypt",
			Count: 3, PolicyARN: "p", PolicyType: "SCP"},
		{Kind: activityDeniedEventAccess, Service: "iam.amazonaws.com", EventName: "ListRoles", Count: 1, ErrorMessage: "denied"},
	}
}

func TestApplyRoleActivity(t *testing.T) {
	role := &models.Role{}
	ApplyRoleActivity(role, roleItems())
	if role.TopEventNames["s3.amazonaws.com:GetObject"] != 2 || role.TopDeniedEventNames["kms.amazonaws.com:Decrypt"] != 3 {
		t.Fatalf("events = %v / %v", role.TopEventNames, role.TopDeniedEventNames)
	}
	if role.ServicesCount["s3.amazonaws.com"] != 2 || strings.Join(role.ServicesUsed, ",") != "kms.amazonaws.com,s3.amazonaws.com" {
		t.Fatalf("services = %v %v", role.ServicesCount, role.ServicesUsed)
	}
	if len(role.ResourceAccesses) != 1 || role.ResourceAccesses[0].Count != 2 || role.ResourcesCount["s3:bucket:a"] != 2 {
		t.Fatalf("accesses = %+v", role.ResourceAccesses)
	}
	if role.DeniedResourceAccesses[0].Count != 3 || role.DeniedResourceAccesses[0].PolicyType != "SCP" {
		t.Fatalf("denied = %+v", role.DeniedResourceAccesses)
	}
	if len(role.DeniedEventAccesses) != 1 || role.DeniedEventAccesses[0].ErrorMessage != "denied" {
		t.Fatalf("denied events = %+v", role.DeniedEventAccesses)
	}
}

// A role not written since the upgrade still has its inline maps and no
// activity items; they are shown as stored.
func TestApplyRoleActivityLeavesUnwrittenLegacyRolesAsStored(t *testing.T) {
	role := &models.Role{
		TopEventNames:  map[string]int{"s3.amazonaws.com:GetObject": 40},
		ResourcesCount: map[string]int{"s3:bucket:a": 40},
		ResourcesUsed:  []string{"s3:bucket:a"},
	}
	ApplyRoleActivity(role, nil)
	if role.TopEventNames["s3.amazonaws.com:GetObject"] != 40 || role.ResourcesCount["s3:bucket:a"] != 40 {
		t.Fatalf("role = %+v", role)
	}
}

func TestApplyServiceActivity(t *testing.T) {
	svc := &models.Service{}
	ApplyServiceActivity(svc, []ActivityItem{
		{Kind: activityEvent, Name: "GetObject", Allowed: map[string]int{"GetObject": 2}, Denied: map[string]int{"GetObject": 1}},
		{Kind: activityEvent, Name: "PutObject", Allowed: map[string]int{"PutObject": 5}},
	})
	if svc.TopEventNames["GetObject"] != 2 || svc.TopEventNames["PutObject"] != 5 || svc.TopDeniedEventNames["GetObject"] != 1 {
		t.Fatalf("service = %+v", svc)
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
