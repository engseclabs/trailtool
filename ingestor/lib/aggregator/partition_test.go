// Partition-invariance property tests (§8.3). CloudTrail lands in arbitrarily
// split, arbitrarily ordered S3 files, and EventBridge/Lambda give no ordering
// or single-delivery guarantee. The identity-first model claims that anchored
// sessions have deterministic keys, so the *same* event set produces the *same*
// anchored sessions no matter how it is partitioned into batches — and that no
// partition ever merges two people's events into one session.
//
// These properties are checked by replaying each fixture (and the union of all
// fixtures) through many random batch splits and comparing the cross-batch
// merged result against the single-batch baseline.
//
// Scope: anchored sessions only (sk = sis#/web#/key#). Windowed (win#) fallback
// sessions are excluded because their cross-batch reconciliation lives in a
// different layer than this harness models. An anchored session has a
// deterministic key, so two batches' contributions merge by exact ref via
// MergeSession — precisely the DynamoDB read-merge-put this test replays. A
// windowed session's key is the sticky first-written start of an idle-gap run,
// so two batches of one run get *different* refs and are stitched back together
// only by foldWindows in the DynamoDB write path (ddbClient != nil), which this
// nil-client harness bypasses. That windowed reconciliation — extend, bridge,
// conflict-retry — is covered directly by TestFoldWindows*/TestWriteWindowedSession*
// (§9.2). The property under test here is the deterministic-key guarantee.
package aggregator

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// fixtureFiles are the end-to-end CloudTrail fixtures replayed through the
// partition harness. Each is a real-shaped {"Records":[...]} capture.
var fixtureFiles = []string{
	"cli_session",
	"aws_login_session",
	"console_session",
	"aws_mcp_agent_session",
	"sso_login_session",
	"clickops",
	"access_denied",
}

// loadFixture reads a testdata CloudTrail capture and returns its records.
func loadFixture(t *testing.T, name string) []types.CloudTrailRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name+".json"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var ctLog struct {
		Records []types.CloudTrailRecord `json:"Records"`
	}
	if err := json.Unmarshal(data, &ctLog); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	return ctLog.Records
}

// aggregateBatches replays events split into batches, feeding each batch through
// the same resolve→aggregate→persist-links path production uses across S3 files:
// the identity links a batch registers seed the next batch's stored links (as
// trailtool-identity-links would), and anchored sessions sharing a deterministic
// key merge additively via MergeSession (as DynamoDB read-merge-put would). It
// returns the final merged session set keyed by session ref (person_key|sk).
func aggregateBatches(t *testing.T, batches [][]types.CloudTrailRecord) map[string]*types.DynamoDBSession {
	t.Helper()
	merged := make(map[string]*types.DynamoDBSession)
	stored := make(map[string]*link)
	for _, batch := range batches {
		// Persist this batch's links for later batches — resolveGroups seeds
		// itself from stored and returns stored extended with in-batch
		// registrations, which is exactly what writeIdentityLinks flushes.
		_, links := resolveGroups(identity.GroupEvents(dedupeByEventID(batch)), stored)
		stored = links

		sessions, err := aggregateForTest(batch, stored)
		if err != nil {
			t.Fatalf("aggregate batch: %v", err)
		}
		for ref, s := range sessions {
			if existing, ok := merged[ref]; ok {
				merged[ref] = ddblib.MergeSession(existing, s)
			} else {
				merged[ref] = s
			}
		}
	}
	return merged
}

// anchoredFingerprint reduces a session set to the deterministic facts a
// partition must not change: for every anchored session, its ref → (anchor,
// total event count, denied count). These follow only from the deterministic
// session key and additive merges, so they are order-independent.
//
// Session *type* is deliberately excluded. login/agent typing is applied when
// the grantee session is created and depends on the grant link being visible in
// that batch or a prior one; a grant arriving in a later batch leaves the type
// as plain cli (the accepted "grantee-side cross-batch attribution gap" in
// TODO.md). That gap is pinned separately by TestCrossBatchTypeAttributionGap
// rather than folded into the strict invariant here. Windowed (win#) sessions
// are excluded entirely — their keys are batch-boundary dependent by design.
func anchoredFingerprint(sessions map[string]*types.DynamoDBSession) map[string]string {
	fp := make(map[string]string)
	for ref, s := range sessions {
		if strings.HasPrefix(s.SK, "win#") {
			continue
		}
		fp[ref] = fmt.Sprintf("anchor=%s events=%d denied=%d", s.Anchor, s.EventsCount, s.DeniedEventCount)
	}
	return fp
}

// randomPartition splits events into batches by assigning each event to one of
// `batchCount` batches at random, then shuffling each batch's internal order.
// This exercises both cross-file splitting and intra-file reordering — the two
// degrees of freedom S3/CloudTrail delivery has.
func randomPartition(rng *rand.Rand, events []types.CloudTrailRecord, batchCount int) [][]types.CloudTrailRecord {
	batches := make([][]types.CloudTrailRecord, batchCount)
	for _, e := range events {
		b := rng.Intn(batchCount)
		batches[b] = append(batches[b], e)
	}
	for _, batch := range batches {
		rng.Shuffle(len(batch), func(i, j int) { batch[i], batch[j] = batch[j], batch[i] })
	}
	// Shuffle batch order too: file arrival order is arbitrary.
	rng.Shuffle(len(batches), func(i, j int) { batches[i], batches[j] = batches[j], batches[i] })
	return batches
}

// diffFingerprints returns a human-readable description of the first difference
// between two fingerprints, or "" if they are equal.
func diffFingerprints(want, got map[string]string) string {
	keys := make(map[string]bool)
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		if want[k] != got[k] {
			return fmt.Sprintf("ref %q: baseline {%s} != partitioned {%s}", k, want[k], got[k])
		}
	}
	return ""
}

// TestPartitionInvariance asserts that every fixture's anchored sessions are
// identical whether ingested as one batch or as any random split/reordering
// into 2–4 batches. This is the core §8.3 property: deterministic session keys
// make cross-batch ingestion order-independent and idempotent.
func TestPartitionInvariance(t *testing.T) {
	for _, name := range fixtureFiles {
		t.Run(name, func(t *testing.T) {
			events := loadFixture(t, name)
			baseline := anchoredFingerprint(aggregateBatches(t, [][]types.CloudTrailRecord{events}))
			if len(baseline) == 0 {
				t.Logf("fixture %s has no anchored sessions (windowed-only); partition invariance is vacuous", name)
			}

			// Deterministic seed per fixture keeps failures reproducible.
			rng := rand.New(rand.NewSource(int64(len(name)) * 2654435761))
			const trials = 50
			for i := range trials {
				batchCount := 2 + rng.Intn(3) // 2..4 batches
				batches := randomPartition(rng, events, batchCount)
				got := anchoredFingerprint(aggregateBatches(t, batches))
				if diff := diffFingerprints(baseline, got); diff != "" {
					t.Fatalf("partition %d (%d batches) changed anchored sessions:\n%s", i, batchCount, diff)
				}
			}
		})
	}
}

// TestPartitionInvarianceUnion replays the union of every fixture through random
// partitions. Mixing unrelated principals into shared batches stresses group
// separation across identities, not just within one capture.
func TestPartitionInvarianceUnion(t *testing.T) {
	var all []types.CloudTrailRecord
	for _, name := range fixtureFiles {
		all = append(all, loadFixture(t, name)...)
	}
	baseline := anchoredFingerprint(aggregateBatches(t, [][]types.CloudTrailRecord{all}))

	rng := rand.New(rand.NewSource(0x5eed))
	const trials = 100
	for i := range trials {
		batchCount := 2 + rng.Intn(5) // 2..6 batches
		batches := randomPartition(rng, all, batchCount)
		got := anchoredFingerprint(aggregateBatches(t, batches))
		if diff := diffFingerprints(baseline, got); diff != "" {
			t.Fatalf("union partition %d (%d batches) changed anchored sessions:\n%s", i, batchCount, diff)
		}
	}
}

// TestNoCrossPersonMerge asserts that no partition ever folds two people's
// events into one session: within any result, a session ref's person key (the
// prefix before '|') must equal the PersonKey recorded on the session, and two
// distinct people never share a session sort key under the same anchor. Merging
// is keyed on person_key|sk, so a cross-person merge would require two people to
// collide on a full ref — this guards that keys stay person-scoped across
// arbitrary batching.
func TestNoCrossPersonMerge(t *testing.T) {
	var all []types.CloudTrailRecord
	for _, name := range fixtureFiles {
		all = append(all, loadFixture(t, name)...)
	}

	rng := rand.New(rand.NewSource(0xc0ffee))
	const trials = 50
	for i := range trials {
		batchCount := 2 + rng.Intn(4)
		sessions := aggregateBatches(t, randomPartition(rng, all, batchCount))

		// A session's ref must be person_key|sk with a matching PersonKey.
		for ref, s := range sessions {
			refPerson, refSK, ok := strings.Cut(ref, "|")
			if !ok {
				t.Fatalf("partition %d: session ref %q is not person_key|sk", i, ref)
			}
			if refPerson != s.PersonKey {
				t.Fatalf("partition %d: ref person %q != session PersonKey %q (sk=%s)", i, refPerson, s.PersonKey, s.SK)
			}
			if refSK != s.SK {
				t.Fatalf("partition %d: ref sk %q != session SK %q", i, refSK, s.SK)
			}
		}

		// No two distinct people share an (anchor, SK): that would mean one
		// credential boundary resolved to two identities in the same result.
		type anchorSK struct{ anchor, sk string }
		owner := make(map[anchorSK]string)
		for _, s := range sessions {
			if s.Anchor == "" || strings.HasPrefix(s.SK, "win#") {
				continue // windowed keys are person-scoped-by-time, not deterministic
			}
			k := anchorSK{s.Anchor, s.SK}
			if prev, ok := owner[k]; ok && prev != s.PersonKey {
				t.Fatalf("partition %d: anchor %q sk %q claimed by two people %q and %q", i, s.Anchor, s.SK, prev, s.PersonKey)
			}
			owner[k] = s.PersonKey
		}
	}
}

// TestCrossBatchTypeAttributionGap pins the one behavior deliberately left out
// of the strict invariant: login/agent session typing is order-dependent across
// batches. When a grant (aws login's CreateOAuth2Token, or the MCP OAuth grant)
// is ingested in the SAME batch as, or a batch BEFORE, the vended session's
// traffic, the session is typed login/agent. When the grant arrives in a LATER
// batch, the grantee session was already created as plain cli and is not
// re-typed — the accepted "grantee-side cross-batch attribution gap" (TODO.md).
//
// This is intentionally a characterization test, not an aspiration: it fails
// loudly if the behavior changes in EITHER direction (e.g. if a future back-
// patch closes the gap, or if same-batch typing regresses), forcing this file
// and TODO.md to be updated together.
func TestCrossBatchTypeAttributionGap(t *testing.T) {
	cases := []struct {
		fixture  string
		anchor   string // anchor of the grantee session under test
		wantType string // type when grant is co-batch/earlier
	}{
		{"aws_login_session", "key#ASIAUB266OVZDVEW755K", "login"},
		{"aws_mcp_agent_session", "sis#arn:aws:signin:us-east-1:278835131762:session/a90e1d90-b08a-4ecf-ac06-e45576d13b98", "agent"},
	}

	// typeOf returns the session type of the anchored session with the given
	// anchor, or "" if absent.
	typeOf := func(sessions map[string]*types.DynamoDBSession, anchor string) string {
		for _, s := range sessions {
			if s.Anchor == anchor {
				return s.SessionType
			}
		}
		return ""
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			events := loadFixture(t, tc.fixture)

			// Single batch: grant and traffic together → attributed.
			single := aggregateBatches(t, [][]types.CloudTrailRecord{events})
			if got := typeOf(single, tc.anchor); got != tc.wantType {
				t.Fatalf("single-batch: session %s typed %q, want %q", tc.anchor, got, tc.wantType)
			}

			// Separate the grant events into a strictly LATER batch than the
			// vended traffic, reproducing the accepted gap: the grantee session
			// is written first as cli and never re-typed.
			var traffic, grant []types.CloudTrailRecord
			for _, e := range events {
				if isGrantEvent(e) {
					grant = append(grant, e)
				} else {
					traffic = append(traffic, e)
				}
			}
			if len(grant) == 0 {
				t.Fatalf("fixture %s has no grant event to defer", tc.fixture)
			}
			deferred := aggregateBatches(t, [][]types.CloudTrailRecord{traffic, grant})
			if got := typeOf(deferred, tc.anchor); got != "cli" {
				t.Fatalf("grant-in-later-batch: session %s typed %q, want %q (accepted gap — if this now matches %q, the back-patch landed; update TODO.md and the strict fingerprint)", tc.anchor, got, "cli", tc.wantType)
			}
		})
	}
}

// isGrantEvent reports whether e is an OAuth grant that types a downstream
// session (aws login PKCE grant or MCP OAuth grant): CreateOAuth2Token on
// signin.amazonaws.com. Used only by the type-attribution gap test to split the
// grant into a later batch than the traffic it would otherwise attribute.
func isGrantEvent(e types.CloudTrailRecord) bool {
	return e.EventSource == "signin.amazonaws.com" && e.EventName == "CreateOAuth2Token"
}
