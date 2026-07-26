package replay

import (
	"context"
	"fmt"
)

// Lister streams object keys under a prefix in ascending order. For CloudTrail's
// date-partitioned layout under a single account/region prefix, ascending key
// order is chronological order (docs/design/cloudtrail-replay.md §5). The
// AWS-backed implementation pages ListObjectsV2; tests use an in-memory fake.
type Lister interface {
	ListKeys(ctx context.Context, prefix string) ([]string, error)
}

// Invoker processes one S3 object through the ingestor. The AWS-backed
// implementation invokes the Lambda synchronously with a synthetic S3 event;
// tests record the calls.
type Invoker interface {
	Invoke(ctx context.Context, bucket, key string) error
}

// Options configure one replay run.
type Options struct {
	Bucket   string
	Prefixes []string // one or more S3 key prefixes, listed and replayed in order
	DryRun   bool     // list and count only; never invoke
}

// Result summarizes a replay run.
type Result struct {
	Matched   int      `json:"matched"`   // replayable objects found in range
	Processed int      `json:"processed"` // successfully invoked (0 on dry-run)
	Failed    []string `json:"failed"`    // keys whose invocation errored, in order
}

// Progress receives per-object status so the CLI can render a live counter.
type Progress func(done, total int, key string)

// Run replays every replayable CloudTrail object under the selected prefixes,
// sequentially and in ascending (chronological) order. Sequential invocation is
// a correctness requirement, not a tuning choice: cross-file attribution is
// order-sensitive and never repaired later, so objects must reach the ingestor
// in order (docs/design/cloudtrail-replay.md §6-7).
//
// A single object's failure is recorded and the run continues. Run holds no
// persistent state: a re-run lists the full range again and relies on the
// ingestor's file marker to skip objects already done within an uninterrupted,
// non-overlapping window (§8).
func Run(ctx context.Context, l Lister, inv Invoker, opts Options, progress Progress) (Result, error) {
	var res Result

	// Two passes so progress totals are known up front and dry-run is cheap: the
	// listing pass fixes the object set, the invocation pass streams through it
	// in order.
	keys, err := listReplayable(ctx, l, opts.Prefixes)
	if err != nil {
		return res, err
	}
	res.Matched = len(keys)

	if opts.DryRun {
		return res, nil
	}

	for i, key := range keys {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := inv.Invoke(ctx, opts.Bucket, key); err != nil {
			res.Failed = append(res.Failed, key)
		} else {
			res.Processed++
		}
		if progress != nil {
			progress(i+1, len(keys), key)
		}
	}
	return res, nil
}

// listReplayable lists every prefix in order and keeps the replayable keys in
// the order S3 returned them. The CLI only ever produces single-account/region
// prefixes, which S3 returns in ascending (chronological) order, so there is
// nothing to re-sort or de-duplicate across prefixes.
func listReplayable(ctx context.Context, l Lister, prefixes []string) ([]string, error) {
	var keys []string
	for _, prefix := range prefixes {
		listed, err := l.ListKeys(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("list %q: %w", prefix, err)
		}
		for _, key := range listed {
			if IsReplayable(key) {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}
