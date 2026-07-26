package store

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestDerivedTablesIncludesMarkersAndLinks(t *testing.T) {
	tables := DerivedTables()
	want := map[string]bool{
		IngestedFilesTableName: false,
		IdentityLinksTableName: false,
		RelationsTableName:     false,
		SessionsTableName:      false,
	}
	for _, tbl := range tables {
		if _, ok := want[tbl]; ok {
			want[tbl] = true
		}
	}
	for tbl, seen := range want {
		if !seen {
			t.Errorf("DerivedTables() missing %q; reset would leave it behind", tbl)
		}
	}
}

func TestKeyProjectionUsesPlaceholdersForReservedWords(t *testing.T) {
	// "name" and "arn" would be problematic bare; placeholders avoid reserved-word
	// collisions and are what the delete scan projects.
	proj, names := keyProjection([]string{"pk", "sk"})
	if proj != "#k0, #k1" {
		t.Fatalf("projection = %q, want %q", proj, "#k0, #k1")
	}
	if names["#k0"] != "pk" || names["#k1"] != "sk" {
		t.Fatalf("names = %#v", names)
	}
}

func TestKeyOnlyProjectsOnlyKeyAttrs(t *testing.T) {
	item := map[string]types.AttributeValue{
		"pk":    &types.AttributeValueMemberS{Value: "a"},
		"sk":    &types.AttributeValueMemberS{Value: "b"},
		"other": &types.AttributeValueMemberS{Value: "c"},
	}
	key := keyOnly(item, []string{"pk", "sk"})
	if len(key) != 2 {
		t.Fatalf("key has %d attrs, want 2: %#v", len(key), key)
	}
	if _, ok := key["other"]; ok {
		t.Fatal("keyOnly kept a non-key attribute")
	}
}

func TestChunkItems(t *testing.T) {
	items := make([]map[string]types.AttributeValue, 55)
	chunks := chunkItems(items, 25)
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	if len(chunks[0]) != 25 || len(chunks[1]) != 25 || len(chunks[2]) != 5 {
		t.Fatalf("chunk sizes = %d,%d,%d", len(chunks[0]), len(chunks[1]), len(chunks[2]))
	}
	if chunkItems(nil, 25) != nil {
		t.Fatal("chunkItems(nil) should be nil")
	}
}
