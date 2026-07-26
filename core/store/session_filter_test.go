package store

import (
	"testing"
	"time"

	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/engseclabs/trailtool/core/models"
)

func TestStartTimeAfter(t *testing.T) {
	t.Run("Days derives a window", func(t *testing.T) {
		f := SessionFilter{Days: 7}
		got := f.startTimeAfter()
		parsed, err := time.Parse(time.RFC3339, got)
		if err != nil {
			t.Fatalf("startTimeAfter = %q, not RFC3339: %v", got, err)
		}
		// ~7 days ago, allowing a few seconds of test runtime.
		want := time.Now().AddDate(0, 0, -7)
		if diff := parsed.Sub(want); diff < -time.Minute || diff > time.Minute {
			t.Fatalf("Days=7 window = %v, want within a minute of %v", parsed, want)
		}
	})

	t.Run("neither yields empty", func(t *testing.T) {
		if got := (SessionFilter{}).startTimeAfter(); got != "" {
			t.Fatalf("startTimeAfter = %q, want empty", got)
		}
	})
}

func TestSessionFilterValidation(t *testing.T) {
	tests := []SessionFilter{
		{Days: -1},
		{Days: 1, After: "2026-07-01T00:00:00Z"},
		{After: "not-a-time"},
		{Before: "not-a-time"},
		{After: "2026-07-10T00:00:00Z", Before: "2026-07-01T00:00:00Z"},
		{SessionType: "unknown"},
	}
	for _, filter := range tests {
		if err := filter.Validate(); err == nil {
			t.Fatalf("filter %#v was accepted", filter)
		}
	}
	for _, sessionType := range []string{"", "cli", "web", "agent", "login"} {
		if err := (SessionFilter{SessionType: sessionType}).Validate(); err != nil {
			t.Fatalf("type %q rejected: %v", sessionType, err)
		}
	}

	normalized, err := (SessionFilter{After: "2026-07-01T01:00:00+01:00"}).normalize()
	if err != nil || normalized.After != "2026-07-01T00:00:00Z" {
		t.Fatalf("normalized filter = %#v, %v", normalized, err)
	}

	normalized, err = (SessionFilter{Days: 7}).normalize()
	if err != nil || normalized.Days != 0 || normalized.After == "" {
		t.Fatalf("normalized days filter = %#v, %v", normalized, err)
	}
}

func TestNonTimeFilter(t *testing.T) {
	t.Run("empty when no role or account", func(t *testing.T) {
		vals := map[string]ddbtypes.AttributeValue{}
		if got := (SessionFilter{After: "2026-07-01T00:00:00Z"}).nonTimeFilter(vals); got != "" {
			t.Fatalf("nonTimeFilter = %q, want empty (time bounds are not filters here)", got)
		}
		if len(vals) != 0 {
			t.Fatalf("nonTimeFilter bound %d values, want 0", len(vals))
		}
	})

	t.Run("account is exact match", func(t *testing.T) {
		vals := map[string]ddbtypes.AttributeValue{}
		got := (SessionFilter{AccountID: "111122223333"}).nonTimeFilter(vals)
		if got != "account_id = :accountId" {
			t.Fatalf("nonTimeFilter = %q", got)
		}
		if v, ok := vals[":accountId"].(*ddbtypes.AttributeValueMemberS); !ok || v.Value != "111122223333" {
			t.Fatalf("account value not bound: %#v", vals)
		}
	})

	t.Run("role is exact ARN match", func(t *testing.T) {
		vals := map[string]ddbtypes.AttributeValue{}
		got := (SessionFilter{RoleARN: "arn:aws:iam::111122223333:role/Admin"}).nonTimeFilter(vals)
		if got != "role_arn = :roleArn" {
			t.Fatalf("nonTimeFilter = %q", got)
		}
	})

	t.Run("both are ANDed", func(t *testing.T) {
		vals := map[string]ddbtypes.AttributeValue{}
		got := (SessionFilter{RoleARN: "arn:aws:iam::111122223333:role/Admin", AccountID: "111122223333"}).nonTimeFilter(vals)
		if got != "account_id = :accountId AND role_arn = :roleArn" {
			t.Fatalf("nonTimeFilter = %q", got)
		}
	})

	t.Run("type and denied are stored predicates", func(t *testing.T) {
		vals := map[string]ddbtypes.AttributeValue{}
		got := (SessionFilter{SessionType: "agent", HasDenied: true}).nonTimeFilter(vals)
		if got != "session_type = :sessionType AND denied_event_count > :zero" {
			t.Fatalf("nonTimeFilter = %q", got)
		}
	})
}

// TestFilterValuesStillCombinesEverything guards the per-user Query expression
// builder after the time bounds were factored out into startTimeAfter.
func TestFilterValuesStillCombinesEverything(t *testing.T) {
	vals := map[string]ddbtypes.AttributeValue{}
	f := SessionFilter{
		After:   "2026-07-01T00:00:00Z",
		Before:  "2026-07-10T00:00:00Z",
		RoleARN: "arn:aws:iam::111122223333:role/Admin",
	}
	got := f.filterValues(vals)
	want := "start_time >= :after AND start_time < :before AND role_arn = :roleArn"
	if got != want {
		t.Fatalf("filterValues = %q, want %q", got, want)
	}
}

func TestRecencyExpressions(t *testing.T) {
	t.Run("no filter: bare partition key, no filter expr", func(t *testing.T) {
		keyCond, filterExpr, vals := recencyExpressions("cust1", SessionFilter{})
		if keyCond != "customerId = :cid" {
			t.Fatalf("keyCond = %q", keyCond)
		}
		if filterExpr != "" {
			t.Fatalf("filterExpr = %q, want empty", filterExpr)
		}
		if len(vals) != 1 {
			t.Fatalf("bound %d values, want just :cid", len(vals))
		}
	})

	t.Run("after tightens the key condition", func(t *testing.T) {
		keyCond, filterExpr, _ := recencyExpressions("cust1", SessionFilter{After: "2026-07-01T00:00:00Z"})
		if keyCond != "customerId = :cid AND start_time >= :after" {
			t.Fatalf("keyCond = %q", keyCond)
		}
		if filterExpr != "" {
			t.Fatalf("filterExpr = %q, want empty (after is a key condition)", filterExpr)
		}
	})

	t.Run("both bounds use one BETWEEN key condition", func(t *testing.T) {
		keyCond, filterExpr, _ := recencyExpressions("cust1", SessionFilter{
			After:  "2026-07-01T00:00:00Z",
			Before: "2026-07-10T00:00:00Z",
		})
		if keyCond != "customerId = :cid AND start_time BETWEEN :after AND :before" {
			t.Fatalf("keyCond = %q", keyCond)
		}
		if filterExpr != "" {
			t.Fatalf("filterExpr = %q, want empty", filterExpr)
		}
	})

	t.Run("before-only uses the key condition", func(t *testing.T) {
		keyCond, filterExpr, _ := recencyExpressions("cust1", SessionFilter{Before: "2026-07-10T00:00:00Z"})
		if keyCond != "customerId = :cid AND start_time < :before" {
			t.Fatalf("keyCond = %q", keyCond)
		}
		if filterExpr != "" {
			t.Fatalf("filterExpr = %q, want empty", filterExpr)
		}
	})

	t.Run("before stays on the key while role is a filter", func(t *testing.T) {
		keyCond, filterExpr, _ := recencyExpressions("cust1", SessionFilter{
			Before:  "2026-07-10T00:00:00Z",
			RoleARN: "arn:aws:iam::111122223333:role/Admin",
		})
		if keyCond != "customerId = :cid AND start_time < :before" {
			t.Fatalf("keyCond = %q", keyCond)
		}
		want := "role_arn = :roleArn"
		if filterExpr != want {
			t.Fatalf("filterExpr = %q, want %q", filterExpr, want)
		}
	})
}

func TestIndexedSessionExpressions(t *testing.T) {
	roleARN := "arn:aws:iam::111122223333:role/Admin"
	index := sessionIndexQuery{
		indexName:     "role_index",
		partitionName: "role_key",
		partitionKey:  "cust1#" + roleARN,
		roleIsKey:     true,
	}
	keyCond, filterExpr, vals := indexedSessionExpressions(index, SessionFilter{
		RoleARN:     roleARN,
		AccountID:   "111122223333",
		After:       "2026-07-01T00:00:00Z",
		Before:      "2026-07-10T00:00:00Z",
		SessionType: "web",
		HasDenied:   true,
	})
	if keyCond != "role_key = :partition AND start_time BETWEEN :after AND :before" {
		t.Fatalf("keyCond = %q", keyCond)
	}
	wantFilter := "account_id = :accountId AND session_type = :sessionType AND denied_event_count > :zero"
	if filterExpr != wantFilter {
		t.Fatalf("filterExpr = %q, want %q", filterExpr, wantFilter)
	}
	if _, ok := vals[":roleArn"]; ok {
		t.Fatalf("role ARN was redundantly bound as a filter: %#v", vals)
	}
}

func TestSessionMatchesTimeBounds(t *testing.T) {
	filter := SessionFilter{
		After:  "2026-07-01T00:00:00Z",
		Before: "2026-07-10T00:00:00Z",
	}
	tests := []struct {
		start string
		want  bool
	}{
		{start: "2026-06-30T23:59:59Z", want: false},
		{start: "2026-07-01T00:00:00Z", want: true},
		{start: "2026-07-09T23:59:59Z", want: true},
		{start: "2026-07-10T00:00:00Z", want: false},
	}
	for _, test := range tests {
		session := &models.Session{StartTime: test.start}
		if got := sessionMatchesTimeBounds(session, filter); got != test.want {
			t.Fatalf("start %s matched=%t, want %t", test.start, got, test.want)
		}
	}
}

func TestSessionIndexForFilter(t *testing.T) {
	roleARN := "arn:aws:iam::111122223333:role/Admin"
	index, ok := sessionIndexForFilter("cust1", SessionFilter{
		RoleARN:   roleARN,
		AccountID: "111122223333",
	})
	if !ok || index.indexName != "role_index" || index.partitionKey != "cust1#"+roleARN {
		t.Fatalf("role plan = %#v, %t", index, ok)
	}

	index, ok = sessionIndexForFilter("cust1", SessionFilter{AccountID: "111122223333"})
	if !ok || index.indexName != "account_index" || index.partitionKey != "cust1#111122223333" {
		t.Fatalf("account plan = %#v, %t", index, ok)
	}

	if index, ok = sessionIndexForFilter("cust1", SessionFilter{}); ok {
		t.Fatalf("empty filter unexpectedly chose %#v", index)
	}
}
