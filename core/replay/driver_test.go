package replay

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
)

// fakeLister returns canned keys per prefix.
type fakeLister struct{ byPrefix map[string][]string }

func (f fakeLister) ListKeys(_ context.Context, prefix string) ([]string, error) {
	return f.byPrefix[prefix], nil
}

// fakeInvoker records invoked keys and fails those in failKeys.
type fakeInvoker struct {
	mu       sync.Mutex
	invoked  []string
	failKeys map[string]bool
}

func (f *fakeInvoker) Invoke(_ context.Context, _, key string) error {
	f.mu.Lock()
	f.invoked = append(f.invoked, key)
	f.mu.Unlock()
	if f.failKeys[key] {
		return errors.New("boom")
	}
	return nil
}

// memCursor is an in-memory Cursor.
type memCursor struct {
	val   string
	saved []string
}

func (c *memCursor) Load(context.Context) (string, error) { return c.val, nil }
func (c *memCursor) Save(_ context.Context, key string) error {
	c.val = key
	c.saved = append(c.saved, key)
	return nil
}

func keysOf(prefix string, names ...string) map[string][]string {
	return map[string][]string{prefix: names}
}

func TestRunInvokesReplayableKeysInOrder(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/",
		"p/a.json.gz",
		"p/CloudTrail-Digest/d.json.gz", // filtered
		"p/b.json.gz",
		"p/notes.txt", // filtered
	)}
	inv := &fakeInvoker{}
	res, err := Run(context.Background(), l, inv, nil, Options{Bucket: "bkt", Prefixes: []string{"p/"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 2 || res.Processed != 2 {
		t.Fatalf("matched=%d processed=%d, want 2/2", res.Matched, res.Processed)
	}
	sort.Strings(inv.invoked)
	if len(inv.invoked) != 2 || inv.invoked[0] != "p/a.json.gz" || inv.invoked[1] != "p/b.json.gz" {
		t.Fatalf("invoked = %v", inv.invoked)
	}
}

func TestDryRunListsButNeverInvokes(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz")}
	inv := &fakeInvoker{}
	res, err := Run(context.Background(), l, inv, nil,
		Options{Bucket: "bkt", Prefixes: []string{"p/"}, DryRun: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 2 || res.Processed != 0 {
		t.Fatalf("matched=%d processed=%d, want 2/0", res.Matched, res.Processed)
	}
	if len(inv.invoked) != 0 {
		t.Fatalf("dry run invoked: %v", inv.invoked)
	}
}

func TestResumeCursorSkipsCompletedKeys(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz", "p/c.json.gz")}
	inv := &fakeInvoker{}
	cur := &memCursor{val: "p/b.json.gz"} // a and b already done
	res, err := Run(context.Background(), l, inv, cur, Options{Bucket: "bkt", Prefixes: []string{"p/"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 2 || res.Processed != 1 {
		t.Fatalf("skipped=%d processed=%d, want 2/1", res.Skipped, res.Processed)
	}
	if len(inv.invoked) != 1 || inv.invoked[0] != "p/c.json.gz" {
		t.Fatalf("invoked = %v, want only c", inv.invoked)
	}
}

func TestCursorAdvancesOnlyToContiguousSuccess(t *testing.T) {
	// b fails; the cursor must stop at a (not jump to c/d), so a resume re-runs b.
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz", "p/c.json.gz", "p/d.json.gz")}
	inv := &fakeInvoker{failKeys: map[string]bool{"p/b.json.gz": true}}
	cur := &memCursor{}
	res, err := Run(context.Background(), l, inv, cur, Options{Bucket: "bkt", Prefixes: []string{"p/"}, Concurrency: 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 || res.Failed[0] != "p/b.json.gz" {
		t.Fatalf("failed = %v", res.Failed)
	}
	if cur.val != "p/a.json.gz" {
		t.Fatalf("cursor = %q, want p/a.json.gz (must not advance past the failure)", cur.val)
	}
}

func TestRunDedupesOverlappingPrefixes(t *testing.T) {
	l := fakeLister{byPrefix: map[string][]string{
		"p/1/": {"p/1/a.json.gz"},
		"p/":   {"p/1/a.json.gz", "p/2/b.json.gz"}, // overlaps p/1/
	}}
	inv := &fakeInvoker{}
	res, err := Run(context.Background(), l, inv, nil,
		Options{Bucket: "bkt", Prefixes: []string{"p/1/", "p/"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 2 || res.Processed != 2 {
		t.Fatalf("matched=%d processed=%d, want 2/2 (a.json.gz deduped)", res.Matched, res.Processed)
	}
}

func TestProgressReportsEveryObject(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz")}
	inv := &fakeInvoker{}
	var mu sync.Mutex
	maxTotal, calls := 0, 0
	progress := func(done, total int, _ string) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		maxTotal = total
	}
	if _, err := Run(context.Background(), l, inv, nil,
		Options{Bucket: "bkt", Prefixes: []string{"p/"}, Concurrency: 2}, progress); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || maxTotal != 2 {
		t.Fatalf("progress calls=%d total=%d, want 2/2", calls, maxTotal)
	}
}

func TestContiguousHighWater(t *testing.T) {
	keys := []string{"a", "b", "c", "d"}
	if got := contiguousHighWater(keys, []bool{true, true, false, true}); got != "b" {
		t.Errorf("high-water = %q, want b", got)
	}
	if got := contiguousHighWater(keys, []bool{true, true, true, true}); got != "d" {
		t.Errorf("all-ok high-water = %q, want d", got)
	}
	if got := contiguousHighWater(keys, []bool{false, true, true, true}); got != "" {
		t.Errorf("first-failed high-water = %q, want empty", got)
	}
}
