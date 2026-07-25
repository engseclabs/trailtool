package models

import (
	"encoding/json"
	"testing"
)

func TestPersonDetailJSONKeepsBaseFieldsAndAddsRelated(t *testing.T) {
	detail := PersonDetail{
		Person:  Person{Pid: "abcdef", PersonKey: "email#alice@example.com", EventsCount: 3},
		Related: NewRelatedNouns(),
	}
	data, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["person_key"] != "email#alice@example.com" || got["events_count"] != float64(3) {
		t.Fatalf("base fields moved or changed: %s", data)
	}
	related, ok := got["related"].(map[string]any)
	if !ok {
		t.Fatalf("related payload missing: %s", data)
	}
	for _, kind := range []string{"people", "sessions", "accounts", "roles", "services", "resources"} {
		values, ok := related[kind].([]any)
		if !ok || len(values) != 0 {
			t.Fatalf("related.%s = %#v, want []", kind, related[kind])
		}
	}
}

func TestResourceDetailJSONIncludesRelationshipBounds(t *testing.T) {
	related := NewRelatedNouns()
	related.Roles = append(related.Roles, RelatedRole{
		Role: Role{ARN: "arn:aws:iam::123456789012:role/Deploy"},
		RelationshipBounds: RelationshipBounds{
			RelationshipFirstSeen: "2026-07-01T00:00:00Z",
			RelationshipLastSeen:  "2026-07-24T00:00:00Z",
		},
	})
	data, err := json.Marshal(ResourceDetail{
		Resource: Resource{Rid: "abcdef", Identifier: "lambda:function:worker", AccountID: "123456789012"},
		Related:  related,
	})
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	roles := got["related"].(map[string]any)["roles"].([]any)
	role := roles[0].(map[string]any)
	if role["arn"] != "arn:aws:iam::123456789012:role/Deploy" ||
		role["relationship_last_seen"] != "2026-07-24T00:00:00Z" {
		t.Fatalf("related role = %#v", role)
	}
}

func TestExistingNounDetailJSONKeepsTopLevelFields(t *testing.T) {
	tests := []struct {
		name      string
		detail    any
		field     string
		wantValue string
	}{
		{
			name: "account",
			detail: AccountDetail{
				Account: Account{AccountID: "123456789012"},
				Related: NewRelatedNouns(),
			},
			field: "account_id", wantValue: "123456789012",
		},
		{
			name: "role",
			detail: RoleDetail{
				Role:    Role{ARN: "arn:aws:iam::123456789012:role/Deploy"},
				Related: NewRelatedNouns(),
			},
			field: "arn", wantValue: "arn:aws:iam::123456789012:role/Deploy",
		},
		{
			name: "service",
			detail: ServiceDetail{
				Service: Service{EventSource: "lambda.amazonaws.com"},
				Related: NewRelatedNouns(),
			},
			field: "event_source", wantValue: "lambda.amazonaws.com",
		},
		{
			name: "session",
			detail: SessionDetail{
				Session: Session{Sid: "abcdef"},
				Related: NewRelatedNouns(),
			},
			field: "sid", wantValue: "abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.detail)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got[tt.field] != tt.wantValue {
				t.Fatalf("%s = %#v, want %q: %s", tt.field, got[tt.field], tt.wantValue, data)
			}
			if _, ok := got["related"].(map[string]any); !ok {
				t.Fatalf("related payload missing: %s", data)
			}
		})
	}
}
