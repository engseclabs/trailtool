package store

import (
	"testing"
	"time"

	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestStartTimeAfter(t *testing.T) {
	t.Run("After wins over Days", func(t *testing.T) {
		f := SessionFilter{After: "2026-07-01T00:00:00Z", Days: 7}
		if got := f.startTimeAfter(); got != "2026-07-01T00:00:00Z" {
			t.Fatalf("startTimeAfter = %q, want the explicit After", got)
		}
	})

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

	t.Run("role is substring match", func(t *testing.T) {
		vals := map[string]ddbtypes.AttributeValue{}
		got := (SessionFilter{Role: "Admin"}).nonTimeFilter(vals)
		if got != "contains(role_name, :role)" {
			t.Fatalf("nonTimeFilter = %q", got)
		}
	})

	t.Run("both are ANDed", func(t *testing.T) {
		vals := map[string]ddbtypes.AttributeValue{}
		got := (SessionFilter{Role: "Admin", AccountID: "111122223333"}).nonTimeFilter(vals)
		if got != "account_id = :accountId AND contains(role_name, :role)" {
			t.Fatalf("nonTimeFilter = %q", got)
		}
	})
}

// TestFilterValuesStillCombinesEverything guards the Scan-path expression
// builder (querySessionPartition, the per-user path) after the time bounds were
// factored out into startTimeAfter: it must still emit the full predicate.
func TestFilterValuesStillCombinesEverything(t *testing.T) {
	vals := map[string]ddbtypes.AttributeValue{}
	f := SessionFilter{After: "2026-07-01T00:00:00Z", Before: "2026-07-10T00:00:00Z", Role: "Admin"}
	got := f.filterValues(vals)
	want := "start_time >= :after AND start_time < :before AND contains(role_name, :role)"
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

	// The critical case: after and before must NOT both land on the sort key —
	// DynamoDB rejects two conditions on one key. after stays on the key,
	// before moves to the filter, preserving the exclusive-< upper bound.
	t.Run("before is a filter, never a second key condition", func(t *testing.T) {
		keyCond, filterExpr, _ := recencyExpressions("cust1", SessionFilter{
			After:  "2026-07-01T00:00:00Z",
			Before: "2026-07-10T00:00:00Z",
		})
		if keyCond != "customerId = :cid AND start_time >= :after" {
			t.Fatalf("keyCond = %q, want only the lower bound on the key", keyCond)
		}
		if filterExpr != "start_time < :before" {
			t.Fatalf("filterExpr = %q, want the exclusive upper bound", filterExpr)
		}
	})

	t.Run("before-only: key stays bare, before is the filter", func(t *testing.T) {
		keyCond, filterExpr, _ := recencyExpressions("cust1", SessionFilter{Before: "2026-07-10T00:00:00Z"})
		if keyCond != "customerId = :cid" {
			t.Fatalf("keyCond = %q", keyCond)
		}
		if filterExpr != "start_time < :before" {
			t.Fatalf("filterExpr = %q", filterExpr)
		}
	})

	t.Run("before and role combine in the filter", func(t *testing.T) {
		_, filterExpr, _ := recencyExpressions("cust1", SessionFilter{
			Before: "2026-07-10T00:00:00Z",
			Role:   "Admin",
		})
		want := "start_time < :before AND contains(role_name, :role)"
		if filterExpr != want {
			t.Fatalf("filterExpr = %q, want %q", filterExpr, want)
		}
	})
}
