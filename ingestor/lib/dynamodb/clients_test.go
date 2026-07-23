package dynamodb

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// cli builds a single-client aggregate for tests.
func cli(key string, total, denied int, first, last string, cmds map[string]int, comps map[string]string, samples ...string) types.ClientAggregate {
	return types.ClientAggregate{
		Key:              key,
		Category:         "cli",
		Name:             "aws-cli",
		TotalEventCount:  total,
		DeniedEventCount: denied,
		FirstSeen:        first,
		LastSeen:         last,
		Commands:         cmds,
		Components:       comps,
		RawUserAgentSamples: append([]string(nil), samples...),
	}
}

// TestMergeClientsOrderIndependent asserts MergeClients(a,b) == MergeClients(b,a)
// and that neither within-slice nor across-slice order affects the result.
func TestMergeClientsOrderIndependent(t *testing.T) {
	a := []types.ClientAggregate{
		cli("cli|aws-cli|2.15|macos|23|arm64|py", 5, 1, "2026-01-01T10:00:00Z", "2026-01-01T10:05:00Z",
			map[string]int{"PutObject": 3, "ua:s3.cp": 2}, map[string]string{"installer": "exe"}, "ua-b", "ua-a"),
		cli("cli|aws-cli|2.16|macos|23|arm64|py", 2, 0, "2026-01-01T11:00:00Z", "2026-01-01T11:01:00Z",
			map[string]int{"ListBuckets": 2}, nil, "ua-c"),
	}
	b := []types.ClientAggregate{
		cli("cli|aws-cli|2.15|macos|23|arm64|py", 4, 0, "2026-01-01T09:55:00Z", "2026-01-01T10:10:00Z",
			map[string]int{"PutObject": 1, "GetObject": 7}, map[string]string{"installer": "brew"}, "ua-a", "ua-d"),
	}

	ab := MergeClients(a, b)
	ba := MergeClients(b, a)
	if !reflect.DeepEqual(ab, ba) {
		t.Fatalf("MergeClients not order-independent:\n a,b = %#v\n b,a = %#v", ab, ba)
	}

	// Reverse within-slice order too.
	arev := []types.ClientAggregate{a[1], a[0]}
	if got := MergeClients(arev, b); !reflect.DeepEqual(got, ab) {
		t.Fatalf("within-slice order changed result:\n want %#v\n got  %#v", ab, got)
	}

	// Spot-check the merged 2.15 row.
	var row *types.ClientAggregate
	for i := range ab {
		if ab[i].Key == "cli|aws-cli|2.15|macos|23|arm64|py" {
			row = &ab[i]
		}
	}
	if row == nil {
		t.Fatal("2.15 row missing")
	}
	if row.TotalEventCount != 9 { // 5 + 4
		t.Errorf("TotalEventCount = %d, want 9", row.TotalEventCount)
	}
	if row.DeniedEventCount != 1 {
		t.Errorf("DeniedEventCount = %d, want 1", row.DeniedEventCount)
	}
	if row.FirstSeen != "2026-01-01T09:55:00Z" {
		t.Errorf("FirstSeen = %q, want the earliest", row.FirstSeen)
	}
	if row.LastSeen != "2026-01-01T10:10:00Z" {
		t.Errorf("LastSeen = %q, want the latest", row.LastSeen)
	}
	if row.Commands["PutObject"] != 4 { // 3 + 1
		t.Errorf("Commands[PutObject] = %d, want 4", row.Commands["PutObject"])
	}
	// Components conflict: "brew" < "exe" lexically, so brew wins deterministically.
	if row.Components["installer"] != "brew" {
		t.Errorf("Components[installer] = %q, want brew (lexically smallest)", row.Components["installer"])
	}
}

// TestMergeClientsSampleCap asserts the retained samples are the lexically
// smallest MaxRawUASamples, regardless of arrival order.
func TestMergeClientsSampleCap(t *testing.T) {
	key := "cli|aws-cli|2.15|macos|23|arm64|py"
	a := []types.ClientAggregate{cli(key, 1, 0, "t", "t", nil, nil, "e", "c", "a")}
	b := []types.ClientAggregate{cli(key, 1, 0, "t", "t", nil, nil, "f", "d", "b", "g")}

	got := MergeClients(a, b)[0].RawUserAgentSamples
	want := []string{"a", "b", "c", "d", "e"} // 7 distinct → smallest 5
	if !reflect.DeepEqual(got, want) {
		t.Errorf("samples = %v, want %v", got, want)
	}
	// Order flip must not change the retained set.
	if got2 := MergeClients(b, a)[0].RawUserAgentSamples; !reflect.DeepEqual(got2, want) {
		t.Errorf("reversed samples = %v, want %v", got2, want)
	}
}

// TestMergeClientsAdditiveNotIdempotent pins the documented contract: counts are
// additive per batch, so folding the same aggregate twice DOUBLES counts. This is
// intentional — redelivery is prevented by the ingested-file guard, not here.
func TestMergeClientsAdditiveNotIdempotent(t *testing.T) {
	x := []types.ClientAggregate{cli("k", 3, 1, "t", "t", map[string]int{"A": 3}, nil)}
	got := MergeClients(x, x)
	if got[0].TotalEventCount != 6 {
		t.Errorf("MergeClients(x,x) TotalEventCount = %d, want 6 (additive by design)", got[0].TotalEventCount)
	}
}

// TestMergeClientsPartitionInvariance folds a fixed set of per-client fragments
// through many random partitions/orderings and asserts every partition yields the
// same merged result as the single-shot baseline.
func TestMergeClientsPartitionInvariance(t *testing.T) {
	// A pool of fragments across 3 client keys, each a "one event" contribution.
	keys := []string{
		"cli|aws-cli|2.15|macos|23|arm64|py",
		"browser|Chrome|120|macos||",
		"agent|claude-code|2.1|||",
	}
	var pool []types.ClientAggregate
	for i := 0; i < 30; i++ {
		k := keys[i%len(keys)]
		ts := fmt.Sprintf("2026-01-01T10:%02d:00Z", i)
		denied := 0
		if i%5 == 0 {
			denied = 1
		}
		pool = append(pool, cli(k, 1, denied, ts, ts,
			map[string]int{fmt.Sprintf("Op%d", i%3): 1}, nil, fmt.Sprintf("ua-%d", i%7)))
	}

	// Baseline: merge everything as one slice (still exercises intra-slice dedupe).
	baseline := MergeClients(pool, nil)

	rng := rand.New(rand.NewSource(1234567))
	for trial := 0; trial < 200; trial++ {
		// Random partition into 1..5 batches, each internally shuffled.
		nb := 1 + rng.Intn(5)
		batches := make([][]types.ClientAggregate, nb)
		for _, frag := range pool {
			bi := rng.Intn(nb)
			batches[bi] = append(batches[bi], frag)
		}
		for _, batch := range batches {
			rng.Shuffle(len(batch), func(i, j int) { batch[i], batch[j] = batch[j], batch[i] })
		}
		rng.Shuffle(nb, func(i, j int) { batches[i], batches[j] = batches[j], batches[i] })

		var acc []types.ClientAggregate
		for _, batch := range batches {
			// Fold each batch to its own aggregate first (dedupe within batch),
			// then merge into the accumulator — mirrors production.
			acc = MergeClients(acc, MergeClients(batch, nil))
		}
		if !reflect.DeepEqual(acc, baseline) {
			t.Fatalf("trial %d (%d batches) diverged from baseline:\n want %#v\n got  %#v", trial, nb, baseline, acc)
		}
	}
}
