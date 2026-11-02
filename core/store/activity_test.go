package store

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/core/models"
)

func TestActivityPartitionMatchesIngestorLayout(t *testing.T) {
	if got := ActivityPartition("default", "s3.amazonaws.com"); got != "default#act#s3.amazonaws.com" {
		t.Fatalf("partition = %q", got)
	}
	// Must match ingestor/lib/dynamodb.ActivityPartition for long IDs.
	long := strings.Repeat("x", 4000)
	if got := ActivityPartition("default", long); got != "default#act#sha256:91c9568c40c8d8d1f7a1bd029d124994" {
		t.Fatalf("hashed partition = %q", got)
	}
}

func TestApplyRoleActivitySumsLegacyAndActivityItems(t *testing.T) {
	// A role mid-migration: legacy inline counts plus activity items.
	role := &models.Role{
		ARN:           "arn:aws:iam::111111111111:role/app",
		TopEventNames: map[string]int{"s3.amazonaws.com:GetObject": 5},
		ServicesCount: map[string]int{"s3.amazonaws.com": 5},
		ResourceAccesses: []models.ResourceAccessItem{{
			Resource: "s3:bucket:a", ResourceAccountID: "111111111111", Service: "s3.amazonaws.com", EventName: "GetObject", Count: 5,
		}},
	}
	ApplyRoleActivity(role, []ActivityItem{
		{Kind: activityEvent, Name: "s3.amazonaws.com", ServiceCount: 2, Allowed: map[string]int{"s3.amazonaws.com:GetObject": 2}},
		{Kind: activityEvent, Name: "kms.amazonaws.com", ServiceCount: 1,
			Allowed: map[string]int{"kms.amazonaws.com:Decrypt": 1}, Denied: map[string]int{"kms.amazonaws.com:Decrypt": 3}},
		{Kind: activityResourceAccess, Resource: "s3:bucket:a", ResourceAccountID: "111111111111", Service: "s3.amazonaws.com", Allowed: map[string]int{"GetObject": 2}},
		{Kind: activityResourceAccess, Resource: "kms:key:k", ResourceAccountID: "111111111111", Service: "kms.amazonaws.com", Allowed: map[string]int{"Decrypt": 1}},
		{Kind: activityDeniedResourceAccess, Resource: "kms:key:k", Service: "kms.amazonaws.com", EventName: "Decrypt", Count: 3, PolicyARN: "p", PolicyType: "SCP"},
		{Kind: activityDeniedEventAccess, Service: "iam.amazonaws.com", EventName: "ListRoles", Count: 1, ErrorMessage: "denied"},
	})
	if role.TopEventNames["s3.amazonaws.com:GetObject"] != 7 || role.TopDeniedEventNames["kms.amazonaws.com:Decrypt"] != 3 {
		t.Fatalf("events = %v / %v", role.TopEventNames, role.TopDeniedEventNames)
	}
	if role.ServicesCount["s3.amazonaws.com"] != 7 || strings.Join(role.ServicesUsed, ",") != "kms.amazonaws.com,s3.amazonaws.com" {
		t.Fatalf("services = %v %v", role.ServicesCount, role.ServicesUsed)
	}
	if len(role.ResourceAccesses) != 2 || role.ResourceAccesses[1].Count != 7 {
		t.Fatalf("resource accesses = %+v", role.ResourceAccesses)
	}
	if role.ResourcesCount["s3:bucket:a"] != 7 || len(role.ResourcesUsed) != 2 {
		t.Fatalf("resources = %v %v", role.ResourcesCount, role.ResourcesUsed)
	}
	if len(role.DeniedResourceAccesses) != 1 || role.DeniedResourceAccesses[0].PolicyType != "SCP" {
		t.Fatalf("denied = %+v", role.DeniedResourceAccesses)
	}
	if len(role.DeniedEventAccesses) != 1 || role.DeniedEventAccesses[0].ErrorMessage != "denied" {
		t.Fatalf("denied events = %+v", role.DeniedEventAccesses)
	}
}

func TestApplyRoleActivityKeepsLegacyRoleUntouchedWithoutItems(t *testing.T) {
	role := &models.Role{
		ResourcesCount: map[string]int{"s3:bucket:a": 3},
		ResourcesUsed:  []string{"s3:bucket:a"},
	}
	ApplyRoleActivity(role, nil)
	if role.ResourcesCount["s3:bucket:a"] != 3 || len(role.ResourcesUsed) != 1 {
		t.Fatalf("legacy role changed: %+v", role)
	}
}

func TestApplyResourceActivityMergesClickOps(t *testing.T) {
	resource := &models.Resource{
		ClickOpsAccesses: []models.ClickOpsAccess{{SessionRef: "p|s1", EventName: "PutBucketPolicy", EventCount: 1}},
	}
	ApplyResourceActivity(resource, []ActivityItem{
		{Kind: activityClickOps, SessionRef: "p|s1", EventName: "PutBucketPolicy", Count: 2},
		{Kind: activityClickOps, SessionRef: "p|s2", EventName: "DeleteBucket", Count: 1, PersonKey: "email#a@example.com", AccessTime: "2026-01-01T00:00:00Z", ResourceAccountID: "111111111111"},
	})
	addInlineEventCounters(resource, map[string]types.AttributeValue{
		"c:PutBucketPolicy": &types.AttributeValueMemberN{Value: "3"},
		"d:DeleteBucket":    &types.AttributeValueMemberN{Value: "1"},
		"total_events":      &types.AttributeValueMemberN{Value: "9"},
	})
	if len(resource.ClickOpsAccesses) != 2 || resource.ClickOpsAccesses[0].EventCount != 3 {
		t.Fatalf("clickops = %+v", resource.ClickOpsAccesses)
	}
	if got := resource.ClickOpsAccesses[1]; got.AccountID != "111111111111" || got.PersonKey != "email#a@example.com" {
		t.Fatalf("new clickops = %+v", got)
	}
	if resource.TopEventNames["PutBucketPolicy"] != 3 || resource.TopDeniedEventNames["DeleteBucket"] != 1 || len(resource.TopEventNames) != 1 {
		t.Fatalf("events = %v", resource.TopEventNames)
	}
}
