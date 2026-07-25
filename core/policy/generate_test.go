package policy

import (
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func TestGeneratePolicyUsesResourceAccount(t *testing.T) {
	role := &models.Role{
		AccountID: "111111111111",
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
