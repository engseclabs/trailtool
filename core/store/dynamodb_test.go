package store

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/engseclabs/trailtool/core/models"
)

func TestNounListSorters(t *testing.T) {
	people := []models.Person{
		{PersonKey: "email#b@example.com", LastSeen: "2026-07-24"},
		{PersonKey: "email#c@example.com", LastSeen: "2026-07-23"},
		{PersonKey: "email#a@example.com", LastSeen: "2026-07-24"},
	}
	sortPeople(people)
	if people[0].PersonKey != "email#a@example.com" ||
		people[1].PersonKey != "email#b@example.com" ||
		people[2].PersonKey != "email#c@example.com" {
		t.Fatalf("people order = %#v", people)
	}
	for i := range people {
		if people[i].Pid == "" {
			t.Fatalf("person %q has no derived PID", people[i].PersonKey)
		}
	}

	roles := []models.Role{
		{ARN: "arn:role/b", LastSeen: "2026-07-24"},
		{ARN: "arn:role/c", LastSeen: "2026-07-23"},
		{ARN: "arn:role/a", LastSeen: "2026-07-24"},
	}
	sortRoles(roles)
	if roles[0].ARN != "arn:role/a" || roles[1].ARN != "arn:role/b" || roles[2].ARN != "arn:role/c" {
		t.Fatalf("roles order = %#v", roles)
	}
	for i := range roles {
		if roles[i].RoleSelector == "" {
			t.Fatalf("role %q has no derived role ID", roles[i].ARN)
		}
	}

	resources := []models.Resource{
		{AccountID: "222", Identifier: "lambda:function:a", LastSeen: "2026-07-24"},
		{AccountID: "111", Identifier: "lambda:function:b", LastSeen: "2026-07-24"},
		{AccountID: "111", Identifier: "lambda:function:a", LastSeen: "2026-07-24"},
	}
	sortResources(resources)
	if resources[0].Identifier != "lambda:function:a" ||
		resources[1].Identifier != "lambda:function:b" ||
		resources[2].AccountID != "222" {
		t.Fatalf("resources order = %#v", resources)
	}
	for i := range resources {
		if resources[i].Rid == "" {
			t.Fatalf("resource %q has no derived RID", resources[i].Identifier)
		}
	}

	accounts := []models.Account{
		{AccountID: "222", LastSeen: "2026-07-24"},
		{AccountID: "333", LastSeen: "2026-07-23"},
		{AccountID: "111", LastSeen: "2026-07-24"},
	}
	sortAccounts(accounts)
	if accounts[0].AccountID != "111" || accounts[1].AccountID != "222" || accounts[2].AccountID != "333" {
		t.Fatalf("accounts order = %#v", accounts)
	}

	services := []models.Service{
		{EventSource: "s3.amazonaws.com", LastSeen: "2026-07-24"},
		{EventSource: "sts.amazonaws.com", LastSeen: "2026-07-23"},
		{EventSource: "lambda.amazonaws.com", LastSeen: "2026-07-24"},
	}
	sortServices(services)
	if services[0].EventSource != "lambda.amazonaws.com" ||
		services[1].EventSource != "s3.amazonaws.com" ||
		services[2].EventSource != "sts.amazonaws.com" {
		t.Fatalf("services order = %#v", services)
	}
}

func TestRolesByRoleIDPrefix(t *testing.T) {
	roles := []models.Role{
		{RoleSelector: "abcdef1aaaaaaaaa", ARN: "arn:aws:iam::111:role/Admin"},
		{RoleSelector: "abcdef2bbbbbbbbb", ARN: "arn:aws:iam::222:role/Admin"},
		{RoleSelector: "ghijkl3ccccccccc", ARN: "arn:aws:iam::111:role/ReadOnly"},
	}

	got := rolesByRoleIDPrefix(roles, "abcdef")
	if len(got) != 2 || got[0].RoleSelector != "abcdef1aaaaaaaaa" || got[1].RoleSelector != "abcdef2bbbbbbbbb" {
		t.Fatalf("prefix matches = %#v", got)
	}
	if got := rolesByRoleIDPrefix(roles, "missing"); len(got) != 0 {
		t.Fatalf("missing prefix matches = %#v", got)
	}
}

func TestRolesByExactName(t *testing.T) {
	roles := []models.Role{
		{ARN: "arn:aws:iam::222:role/Admin", Name: "Admin", AccountID: "222"},
		{ARN: "arn:aws:iam::111:role/Admin", Name: "Admin", AccountID: "111"},
		{ARN: "arn:aws:iam::111:role/AdminReadOnly", Name: "AdminReadOnly", AccountID: "111"},
	}

	got := rolesByExactName(roles, "Admin", "")
	if len(got) != 2 || got[0].AccountID != "111" || got[1].AccountID != "222" {
		t.Fatalf("exact matches = %#v", got)
	}
	scoped := rolesByExactName(roles, "Admin", "222")
	if len(scoped) != 1 || scoped[0].AccountID != "222" {
		t.Fatalf("scoped matches = %#v", scoped)
	}
}

func TestFilterClickOpsActivityFiltersRowsAndRecomputesCount(t *testing.T) {
	resource := &models.Resource{
		ClickOpsCount: 99,
		ClickOpsAccesses: []models.ClickOpsAccess{
			{SessionRef: "old", EventName: "CreateBucket", AccessTime: "2026-06-01T00:00:00Z", EventCount: 4},
			{SessionRef: "before-edge", EventName: "PutBucketPolicy", AccessTime: "2026-06-30T23:59:59Z", EventCount: 6},
			{SessionRef: "at-edge", EventName: "PutBucketPolicy", AccessTime: "2026-07-01T00:00:00Z", EventCount: 5},
			{SessionRef: "new-b", EventName: "PutBucketPolicy", AccessTime: "2026-07-24T11:00:00Z", EventCount: 2},
			{SessionRef: "new-a", EventName: "CreateBucket", AccessTime: "2026-07-24T12:00:00Z", EventCount: 1},
		},
	}

	filterClickOpsActivity(resource, "2026-07-01T00:00:00Z", "")
	if resource.ClickOpsCount != 8 {
		t.Fatalf("clickops_count = %d, want 8", resource.ClickOpsCount)
	}
	if len(resource.ClickOpsAccesses) != 3 {
		t.Fatalf("clickops_accesses = %#v", resource.ClickOpsAccesses)
	}
	if resource.ClickOpsAccesses[0].SessionRef != "new-a" {
		t.Fatalf("clickops order = %#v", resource.ClickOpsAccesses)
	}
}

func TestResourceSeenInDateRangeAcceptsFullTimestampsAtDayBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		lastSeen string
		start    string
		end      string
		want     bool
	}{
		{name: "timestamp on start day", lastSeen: "2026-07-17T23:59:59Z", start: "2026-07-17", want: true},
		{name: "timestamp on end day", lastSeen: "2026-07-24T23:59:59Z", end: "2026-07-24", want: true},
		{name: "legacy date", lastSeen: "2026-07-24", start: "2026-07-24", end: "2026-07-24", want: true},
		{name: "before start", lastSeen: "2026-07-16T23:59:59Z", start: "2026-07-17", want: false},
		{name: "after end", lastSeen: "2026-07-25T00:00:00Z", end: "2026-07-24", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resourceSeenInDateRange(tt.lastSeen, tt.start, tt.end); got != tt.want {
				t.Fatalf("resourceSeenInDateRange(%q, %q, %q) = %t, want %t",
					tt.lastSeen, tt.start, tt.end, got, tt.want)
			}
		})
	}
}

func TestSessionSummaryUpdatePersistsAllMetadata(t *testing.T) {
	sess := &models.Session{
		PersonKey:          "email#alice@example.com",
		SK:                 "key#role",
		Summary:            "Updated a bucket policy.",
		SummaryGeneratedAt: "2026-07-24T12:00:00Z",
		SummaryModel:       "model",
		SummaryTokensUsed:  42,
		SummaryInputDigest: "abc123",
	}
	input, err := sessionSummaryUpdateInput("default", sess)
	if err != nil {
		t.Fatalf("sessionSummaryUpdateInput() error = %v", err)
	}
	if got := input.Key["pk"].(*ddbtypes.AttributeValueMemberS).Value; got != "default#email#alice@example.com" {
		t.Fatalf("pk = %q", got)
	}
	if input.UpdateExpression == nil || !strings.Contains(*input.UpdateExpression, "#input_digest") {
		t.Fatalf("update expression = %v", input.UpdateExpression)
	}
	var values map[string]interface{}
	if err := attributevalue.UnmarshalMap(input.ExpressionAttributeValues, &values); err != nil {
		t.Fatalf("unmarshal values: %v", err)
	}
	for _, key := range []string{":summary", ":generated_at", ":model", ":tokens_used", ":input_digest"} {
		if _, ok := values[key]; !ok {
			t.Fatalf("missing expression value %s: %#v", key, values)
		}
	}
}
