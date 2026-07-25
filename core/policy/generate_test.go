package policy

import (
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func TestGeneratePolicyUsesResourceAccount(t *testing.T) {
	role := &models.Role{
		AccountID: "111111111111",
		TopEventNames: map[string]int{
			"lambda.amazonaws.com:Invoke": 1,
		},
		ResourceAccesses: []models.ResourceAccessItem{{
			Resource:          "lambda:function:shared-function",
			ResourceAccountID: "222222222222",
			Service:           "lambda.amazonaws.com",
			EventName:         "Invoke",
			Count:             1,
		}},
	}

	got, err := GeneratePolicy(role, false)
	if err != nil {
		t.Fatalf("GeneratePolicy() error = %v", err)
	}
	if len(got.Actions) != 1 || len(got.Actions[0].Resources) != 1 {
		t.Fatalf("actions = %#v", got.Actions)
	}
	want := "arn:aws:lambda:*:222222222222:function:shared-function"
	if got.Actions[0].Resources[0] != want {
		t.Fatalf("resource ARN = %q, want %q", got.Actions[0].Resources[0], want)
	}
}

func TestGeneratePolicyFallsBackToRoleAccount(t *testing.T) {
	role := &models.Role{
		AccountID: "111111111111",
		TopEventNames: map[string]int{
			"dynamodb.amazonaws.com:GetItem": 1,
		},
		ResourceAccesses: []models.ResourceAccessItem{{
			Resource:  "dynamodb:table:orders",
			Service:   "dynamodb.amazonaws.com",
			EventName: "GetItem",
			Count:     1,
		}},
	}

	got, err := GeneratePolicy(role, false)
	if err != nil {
		t.Fatalf("GeneratePolicy() error = %v", err)
	}
	if len(got.Actions) != 1 || len(got.Actions[0].Resources) != 1 {
		t.Fatalf("actions = %#v", got.Actions)
	}
	want := "arn:aws:dynamodb:*:111111111111:table/orders"
	if got.Actions[0].Resources[0] != want {
		t.Fatalf("resource ARN = %q, want %q", got.Actions[0].Resources[0], want)
	}
}

func TestGeneratePolicyUsesCanonicalEventCountsOnce(t *testing.T) {
	role := &models.Role{
		AccountID: "111111111111",
		TopEventNames: map[string]int{
			"s3.amazonaws.com:ListBuckets": 4,
			"s3.amazonaws.com:GetObject":   3,
		},
		ResourceAccesses: []models.ResourceAccessItem{{
			Resource:  "s3:bucket:reports",
			Service:   "s3.amazonaws.com",
			EventName: "GetObject",
			Count:     3,
		}},
	}

	got, err := GeneratePolicy(role, false)
	if err != nil {
		t.Fatalf("GeneratePolicy() error = %v", err)
	}

	counts := make(map[string]int, len(got.Actions))
	for _, action := range got.Actions {
		counts[action.Action] = action.Count
	}
	if counts["s3:ListAllMyBuckets"] != 4 {
		t.Fatalf("resource-less action count = %d, want 4; actions = %#v", counts["s3:ListAllMyBuckets"], got.Actions)
	}
	if counts["s3:GetObject"] != 3 {
		t.Fatalf("resource-backed action count = %d, want 3; actions = %#v", counts["s3:GetObject"], got.Actions)
	}
}

func TestGeneratePolicyFromSessionIncludesDeniedAndReportsSID(t *testing.T) {
	sess := &models.Session{
		Sid:       "k7m2qp",
		PersonKey: "email#alice@example.com",
		SK:        "key#role",
		EventCounts: map[string]int{
			"sts.amazonaws.com:GetCallerIdentity": 2,
		},
		DeniedEventCounts: map[string]int{
			"iam.amazonaws.com:DeleteRole": 1,
		},
	}

	got, err := GeneratePolicyFromSession(sess, true)
	if err != nil {
		t.Fatalf("GeneratePolicyFromSession() error = %v", err)
	}
	if got.SessionID != "k7m2qp" {
		t.Fatalf("session_id = %q, want SID", got.SessionID)
	}
	counts := make(map[string]int, len(got.Actions))
	for _, action := range got.Actions {
		counts[action.Action] = action.Count
	}
	if counts["sts:GetCallerIdentity"] != 2 || counts["iam:DeleteRole"] != 1 {
		t.Fatalf("actions = %#v", got.Actions)
	}
}
