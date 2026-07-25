package ingest

import "testing"

func TestTablesFromEnvIncludesRelations(t *testing.T) {
	t.Setenv("RELATIONS_TABLE", "")
	if got := TablesFromEnv("trailtool").Relations; got != "trailtool-relations" {
		t.Fatalf("default relations table = %q, want trailtool-relations", got)
	}

	t.Setenv("RELATIONS_TABLE", "custom-relations")
	if got := TablesFromEnv("trailtool").Relations; got != "custom-relations" {
		t.Fatalf("configured relations table = %q, want custom-relations", got)
	}
}
