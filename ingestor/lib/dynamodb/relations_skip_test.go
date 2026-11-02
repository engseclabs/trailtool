package dynamodb

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"

	"github.com/engseclabs/trailtool/ingestor/lib/dynamodb/ddbfake"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const testRelations = "trailtool-relations"

func relationFixture(at string) []types.DynamoDBRelation {
	return []types.DynamoDBRelation{
		NewRelation("default", RelationKindRole, "arn:aws:iam::111111111111:role/app", RelationKindService, "s3.amazonaws.com", at),
		NewRelation("default", RelationKindService, "s3.amazonaws.com", RelationKindRole, "arn:aws:iam::111111111111:role/app", at),
		NewRelation("default", RelationKindRole, "arn:aws:iam::111111111111:role/app", RelationKindAccount, "111111111111", at),
	}
}

func storedRelation(t *testing.T, store *ddbfake.Store, r types.DynamoDBRelation) types.DynamoDBRelation {
	t.Helper()
	var got types.DynamoDBRelation
	if err := attributevalue.UnmarshalMap(store.Get(testRelations, relationKey(r.PK, r.SK)), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWriteRelationsSkipsUnchangedEdges(t *testing.T) {
	ctx := context.Background()
	store := ddbfake.New(map[string]ddbfake.KeySchema{testRelations: {Hash: "pk", Range: "sk"}})

	first, err := WriteRelations(ctx, store, testRelations, relationFixture("2026-01-01T10:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.NewEdges) != 3 || len(first.NewSubjects) != 2 {
		t.Fatalf("first write: %d edges, %d subjects", len(first.NewEdges), len(first.NewSubjects))
	}

	// The same edges again, and again 59 minutes later: nothing to write.
	store.ResetMeters()
	for _, at := range []string{"2026-01-01T10:00:00Z", "2026-01-01T10:59:00Z"} {
		res, err := WriteRelations(ctx, store, testRelations, relationFixture(at))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.NewEdges) != 0 || len(res.NewSubjects) != 0 {
			t.Fatalf("replay reported new edges %+v", res)
		}
	}
	if wcu := store.Stats()[testRelations].WriteUnits; wcu != 0 {
		t.Fatalf("unchanged edges cost %.0f write units", wcu)
	}

	// An hour later last_seen moves; an earlier observation moves first_seen.
	if _, err := WriteRelations(ctx, store, testRelations, relationFixture("2026-01-01T11:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRelations(ctx, store, testRelations, relationFixture("2026-01-01T09:30:00Z")); err != nil {
		t.Fatal(err)
	}
	for _, r := range relationFixture("") {
		got := storedRelation(t, store, r)
		if got.FirstSeen != "2026-01-01T09:30:00Z" || got.LastSeen != "2026-01-01T11:00:00Z" {
			t.Fatalf("%s/%s bounds = %s..%s", r.PK, r.SK, got.FirstSeen, got.LastSeen)
		}
	}
	if wcu := store.Stats()[testRelations].WriteUnits; wcu != 6 {
		t.Fatalf("two bound moves on 3 edges cost %.0f write units, want 6", wcu)
	}

	counts, err := GetRelationSummaryCounts(ctx, store, testRelations, RelationPK("default", RelationKindRole, "arn:aws:iam::111111111111:role/app"))
	if err != nil {
		t.Fatal(err)
	}
	if counts["services"] != 1 || counts["accounts"] != 1 {
		t.Fatalf("summary counts = %v", counts)
	}
}

func TestLastSeenAdvances(t *testing.T) {
	cases := []struct {
		stored, observed string
		want             bool
	}{
		{"", "2026-01-01T00:00:00Z", true},
		{"2026-01-01T00:00:00Z", "2026-01-01T00:59:59Z", false},
		{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", true},
		{"2026-01-01T02:00:00Z", "2026-01-01T01:00:00Z", false},
		{"2026-01-01", "2026-01-02", true},
	}
	for _, c := range cases {
		if got := lastSeenAdvances(c.stored, c.observed); got != c.want {
			t.Errorf("lastSeenAdvances(%q, %q) = %v", c.stored, c.observed, got)
		}
	}
}
