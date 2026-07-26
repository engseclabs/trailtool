package replay

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Lister streams object keys under a prefix in ascending (lexicographic, hence
// chronological for CloudTrail) order. The AWS-backed implementation pages
// ListObjectsV2; tests use an in-memory fake.
type Lister interface {
	ListKeys(ctx context.Context, prefix string) ([]string, error)
}

// Invoker processes one S3 object through the ingestor. The AWS-backed
// implementation invokes the Lambda synchronously with a synthetic S3 event;
// tests record the calls.
type Invoker interface {
	Invoke(ctx context.Context, bucket, key string) error
}

// Cursor persists the last successfully-processed key so an interrupted replay
// resumes without re-invoking completed objects. A no-op implementation disables
// resume. Load returns "" when no cursor exists yet.
type Cursor interface {
	Load(ctx context.Context) (string, error)
	Save(ctx context.Context, key string) error
}

// Options configure one replay run.
type Options struct {
	Bucket      string
	Prefixes    []string // one or more S3 key prefixes, listed in order
	Concurrency int      // max in-flight invocations (>=1)
	DryRun      bool     // list and count only; never invoke
}

// Result summarizes a replay run.
type Result struct {
	Matched   int      `json:"matched"`   // replayable objects found in range
	Processed int      `json:"processed"` // successfully invoked (0 on dry-run)
	Skipped   int      `json:"skipped"`   // below the resume cursor
	Failed    []string `json:"failed"`    // keys whose invocation errored
}

// Progress receives per-object status so the CLI can render a live counter. It
// is called from the driver's single coordinating goroutine, so implementations
// need not be concurrency-safe.
type Progress func(done, total int, key string)

// Run lists the objects under each prefix, filters to replayable CloudTrail
// logs above the resume cursor, and invokes the ingestor for each with bounded
// concurrency. Objects are ordered chronologically and the cursor advances in
// order, so an interrupted run resumes cleanly (docs/design/cloudtrail-replay.md
// §7-8). A single object's failure is recorded, not fatal.
func Run(ctx context.Context, l Lister, inv Invoker, cur Cursor, opts Options, progress Progress) (Result, error) {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	var res Result

	resume := ""
	if cur != nil {
		var err error
		if resume, err = cur.Load(ctx); err != nil {
			return res, fmt.Errorf("load resume cursor: %w", err)
		}
	}

	keys, err := collectKeys(ctx, l, opts.Prefixes, resume, &res)
	if err != nil {
		return res, err
	}
	res.Matched = len(keys)

	if opts.DryRun || len(keys) == 0 {
		return res, nil
	}

	return runInvocations(ctx, inv, cur, opts, keys, progress, res)
}

// collectKeys lists every prefix, keeps replayable keys strictly above the
// resume cursor, dedupes (adjacent day-prefixes never overlap, but an operator
// can pass overlapping --prefix values), and returns them in ascending order.
func collectKeys(ctx context.Context, l Lister, prefixes []string, resume string, res *Result) ([]string, error) {
	seen := map[string]bool{}
	var keys []string
	for _, prefix := range prefixes {
		listed, err := l.ListKeys(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("list %q: %w", prefix, err)
		}
		for _, key := range listed {
			if !IsReplayable(key) {
				continue
			}
			if resume != "" && key <= resume {
				res.Skipped++
				continue
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// runInvocations invokes the ingestor for each key with bounded concurrency.
// Results are collected in order so the resume cursor only advances past a
// contiguous run of successes: the cursor is set to the highest key for which
// that key and every earlier key succeeded, so a mid-run failure never strands
// an un-replayed gap below the cursor.
func runInvocations(ctx context.Context, inv Invoker, cur Cursor, opts Options, keys []string, progress Progress, res Result) (Result, error) {
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	okByIndex := make([]bool, len(keys))
	done := 0

	for i, key := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, key string) {
			defer wg.Done()
			defer func() { <-sem }()

			err := inv.Invoke(ctx, opts.Bucket, key)

			mu.Lock()
			defer mu.Unlock()
			done++
			if err != nil {
				res.Failed = append(res.Failed, key)
			} else {
				okByIndex[i] = true
				res.Processed++
			}
			if progress != nil {
				progress(done, len(keys), key)
			}
		}(i, key)
	}
	wg.Wait()

	if cur != nil {
		if hwm := contiguousHighWater(keys, okByIndex); hwm != "" {
			if err := cur.Save(ctx, hwm); err != nil {
				return res, fmt.Errorf("save resume cursor at %q: %w", hwm, err)
			}
		}
	}

	sort.Strings(res.Failed)
	return res, nil
}

// contiguousHighWater returns the highest key such that it and every earlier key
// in the (ascending) slice succeeded. Advancing the cursor only to this point
// guarantees resume never skips a failed object.
func contiguousHighWater(keys []string, ok []bool) string {
	hwm := ""
	for i := range keys {
		if !ok[i] {
			break
		}
		hwm = keys[i]
	}
	return hwm
}
