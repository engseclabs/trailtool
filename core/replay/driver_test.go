package replay

import (
	"context"
	"errors"
	"testing"
)

// fakeLister returns canned keys per prefix.
type fakeLister struct{ byPrefix map[string][]string }

func (f fakeLister) ListKeys(_ context.Context, prefix string) ([]string, error) {
	return f.byPrefix[prefix], nil
}

// fakeInvoker records invoked keys in order and fails those in failKeys.
type fakeInvoker struct {
	invoked  []string
	failKeys map[string]bool
}

func (f *fakeInvoker) Invoke(_ context.Context, _, key string) error {
	f.invoked = append(f.invoked, key)
	if f.failKeys[key] {
		return errors.New("boom")
	}
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
	res, err := Run(context.Background(), l, inv, Options{Bucket: "bkt", Prefixes: []string{"p/"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 2 || res.Processed != 2 {
		t.Fatalf("matched=%d processed=%d, want 2/2", res.Matched, res.Processed)
	}
	// Sequential replay must preserve listing (chronological) order exactly.
	if len(inv.invoked) != 2 || inv.invoked[0] != "p/a.json.gz" || inv.invoked[1] != "p/b.json.gz" {
		t.Fatalf("invoked = %v, want [a b] in order", inv.invoked)
	}
}

func TestRunPreservesCrossPrefixOrder(t *testing.T) {
	// Prefixes are replayed in the order given, each in listing order, with no
	// re-sort or dedup: the driver trusts the CLI to pass ordered prefixes.
	l := fakeLister{byPrefix: map[string][]string{
		"p/2026/07/25/": {"p/2026/07/25/a.json.gz"},
		"p/2026/07/26/": {"p/2026/07/26/b.json.gz"},
	}}
	inv := &fakeInvoker{}
	_, err := Run(context.Background(), l, inv,
		Options{Bucket: "bkt", Prefixes: []string{"p/2026/07/25/", "p/2026/07/26/"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.invoked) != 2 || inv.invoked[0] != "p/2026/07/25/a.json.gz" || inv.invoked[1] != "p/2026/07/26/b.json.gz" {
		t.Fatalf("invoked = %v, want day 25 before day 26", inv.invoked)
	}
}

func TestDryRunListsButNeverInvokes(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz")}
	inv := &fakeInvoker{}
	res, err := Run(context.Background(), l, inv,
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

func TestRunRecordsFailuresAndContinues(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz", "p/c.json.gz")}
	inv := &fakeInvoker{failKeys: map[string]bool{"p/b.json.gz": true}}
	res, err := Run(context.Background(), l, inv, Options{Bucket: "bkt", Prefixes: []string{"p/"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// b fails but the run continues through c.
	if res.Processed != 2 {
		t.Fatalf("processed=%d, want 2", res.Processed)
	}
	if len(res.Failed) != 1 || res.Failed[0] != "p/b.json.gz" {
		t.Fatalf("failed = %v, want [p/b.json.gz]", res.Failed)
	}
	if len(inv.invoked) != 3 {
		t.Fatalf("invoked %d objects, want all 3 attempted", len(inv.invoked))
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz")}
	inv := &fakeInvoker{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before any invocation
	_, err := Run(ctx, l, inv, Options{Bucket: "bkt", Prefixes: []string{"p/"}}, nil)
	if err == nil {
		t.Fatal("expected context error")
	}
	if len(inv.invoked) != 0 {
		t.Fatalf("invoked despite cancelled context: %v", inv.invoked)
	}
}

func TestProgressReportsEveryObject(t *testing.T) {
	l := fakeLister{byPrefix: keysOf("p/", "p/a.json.gz", "p/b.json.gz")}
	inv := &fakeInvoker{}
	var seen []int
	progress := func(done, total int, _ string) {
		if total != 2 {
			t.Errorf("total = %d, want 2", total)
		}
		seen = append(seen, done)
	}
	if _, err := Run(context.Background(), l, inv,
		Options{Bucket: "bkt", Prefixes: []string{"p/"}}, progress); err != nil {
		t.Fatal(err)
	}
	// Sequential progress counts up monotonically.
	if len(seen) != 2 || seen[0] != 1 || seen[1] != 2 {
		t.Fatalf("progress = %v, want [1 2]", seen)
	}
}
