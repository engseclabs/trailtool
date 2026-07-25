package store

import (
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func TestPeopleByPIDPrefix(t *testing.T) {
	people := []models.Person{
		{Pid: "abcdef2", PersonKey: "email#second@example.com"},
		{Pid: "abcdef1", PersonKey: "email#first@example.com"},
		{Pid: "otherid", PersonKey: "email#other@example.com"},
	}

	if got := peopleByPIDPrefix(people, "missing"); len(got) != 0 {
		t.Fatalf("no-match prefix returned %#v", got)
	}
	if got := peopleByPIDPrefix(people, "abcdef1"); len(got) != 1 || got[0].PersonKey != "email#first@example.com" {
		t.Fatalf("unique prefix returned %#v", got)
	}
	got := peopleByPIDPrefix(people, "abcdef")
	if len(got) != 2 || got[0].Pid != "abcdef1" || got[1].Pid != "abcdef2" {
		t.Fatalf("ambiguous prefix returned %#v", got)
	}
}

func TestResourcesByRIDPrefix(t *testing.T) {
	resources := []models.Resource{
		{Rid: "abcdef2", AccountID: "222", Identifier: "lambda:function:worker"},
		{Rid: "abcdef1", AccountID: "111", Identifier: "lambda:function:worker"},
		{Rid: "otherid", AccountID: "111", Identifier: "s3:bucket:logs"},
	}

	if got := resourcesByRIDPrefix(resources, "missing"); len(got) != 0 {
		t.Fatalf("no-match prefix returned %#v", got)
	}
	if got := resourcesByRIDPrefix(resources, "abcdef2"); len(got) != 1 || got[0].AccountID != "222" {
		t.Fatalf("unique prefix returned %#v", got)
	}
	got := resourcesByRIDPrefix(resources, "abcdef")
	if len(got) != 2 || got[0].Rid != "abcdef1" || got[1].Rid != "abcdef2" {
		t.Fatalf("ambiguous prefix returned %#v", got)
	}
}

func TestNounRelationsSortByLastSeenThenIdentity(t *testing.T) {
	relations := []nounRelation{
		{RelatedKind: RelationKindRole, RelatedID: "b", LastSeen: "2026-07-24"},
		{RelatedKind: RelationKindService, RelatedID: "a", LastSeen: "2026-07-23"},
		{RelatedKind: RelationKindRole, RelatedID: "a", LastSeen: "2026-07-24"},
	}
	sortNounRelations(relations)

	if relations[0].RelatedID != "a" || relations[1].RelatedID != "b" || relations[2].RelatedKind != RelationKindService {
		t.Fatalf("relation order = %#v", relations)
	}
}

func TestRelationPKMatchesIngestorContract(t *testing.T) {
	got := relationPK("customer", RelationKindPerson, "email#alice@example.com")
	want := "customer#person#ZW1haWwjYWxpY2VAZXhhbXBsZS5jb20"
	if got != want {
		t.Fatalf("relationPK() = %q, want %q", got, want)
	}
}

func TestReachedLimit(t *testing.T) {
	if reachedLimit(1, 0) {
		t.Fatal("zero limit should mean all")
	}
	if !reachedLimit(10, 10) {
		t.Fatal("equal positive limit was not reached")
	}
	if reachedLimit(9, 10) {
		t.Fatal("limit was reached early")
	}
}

func TestMergeNounRelationPageReturnsSummaryAndEdges(t *testing.T) {
	page := []nounRelation{
		{
			SK: relationSummarySK,
			Counts: models.RelationshipCounts{
				People: 7, Sessions: 8,
			},
		},
		{
			SK:          "person#alice",
			RelatedKind: RelationKindPerson,
			RelatedID:   "alice",
		},
	}

	relations, counts := mergeNounRelationPage(nil, models.RelationshipCounts{}, page)
	if len(relations) != 1 || relations[0].RelatedID != "alice" {
		t.Fatalf("relations = %#v", relations)
	}
	if !counts.Exact || counts.People != 7 || counts.Sessions != 8 {
		t.Fatalf("counts = %#v", counts)
	}
}
