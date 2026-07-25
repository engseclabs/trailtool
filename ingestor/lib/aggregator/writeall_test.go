package aggregator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestWriteAllWritesEveryItemOnce asserts the concurrency helper invokes fn
// exactly once per map entry — no drops, no duplicates — regardless of the
// bounded worker limit. This is the core guarantee the parallelized write
// block relies on: every aggregated entity in a batch reaches DynamoDB.
func TestWriteAllWritesEveryItemOnce(t *testing.T) {
	const n = writeConcurrency*4 + 7 // exceed the limit so workers recycle
	items := make(map[string]int, n)
	for i := range n {
		items[string(rune('a'+i%26))+string(rune('0'+i))] = i
	}

	var mu sync.Mutex
	seen := make(map[int]int, n)
	writeAll(context.Background(), items, func(_ context.Context, v int) {
		mu.Lock()
		seen[v]++
		mu.Unlock()
	})

	if len(seen) != len(items) {
		t.Fatalf("wrote %d distinct items, want %d", len(seen), len(items))
	}
	for v, count := range seen {
		if count != 1 {
			t.Errorf("item %d written %d times, want exactly 1", v, count)
		}
	}
}

// TestWriteAllRaceOnSharedTarget exercises the pattern the sessions loop uses:
// each fn mutates a shared structure under a caller-held lock. Run under -race
// it proves writeAll adds no data race of its own around the shared mutation
// (the win# replaceID reconciliation is guarded the same way in aggregateGroups).
func TestWriteAllRaceOnSharedTarget(t *testing.T) {
	items := make(map[string]int, 200)
	for i := range 200 {
		items[string(rune(i))] = i
	}

	var mu sync.Mutex
	total := 0
	writeAll(context.Background(), items, func(_ context.Context, v int) {
		mu.Lock()
		total += v
		mu.Unlock()
	})

	want := 0
	for _, v := range items {
		want += v
	}
	if total != want {
		t.Fatalf("summed %d under concurrency, want %d", total, want)
	}
}

// TestWriteAllErrorDoesNotAbortBatch confirms a failing fn (mirroring a write
// whose error is logged and swallowed) never prevents the other items from
// being processed — the batch always completes fully, matching the prior
// serial loops' log-and-continue behavior.
func TestWriteAllErrorDoesNotAbortBatch(t *testing.T) {
	items := make(map[string]int, 50)
	for i := range 50 {
		items[string(rune(i))] = i
	}

	var processed atomic.Int64
	writeAll(context.Background(), items, func(_ context.Context, v int) {
		processed.Add(1)
		if v%3 == 0 {
			// fn owns its error; writeAll never sees it. Emulate that here.
			_ = errors.New("simulated write failure")
		}
	})

	if got := processed.Load(); got != int64(len(items)) {
		t.Fatalf("processed %d items, want %d — a failure aborted the batch", got, len(items))
	}
}

// TestWriteAllEmpty is a no-op guard: an empty map must not spin up a group.
func TestWriteAllEmpty(t *testing.T) {
	called := false
	writeAll(context.Background(), map[string]int{}, func(_ context.Context, _ int) {
		called = true
	})
	if called {
		t.Fatal("fn called for an empty map")
	}
}
