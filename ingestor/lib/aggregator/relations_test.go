package aggregator

import (
	"testing"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
)

func TestRecordEventRelationsWritesEveryInverseOnce(t *testing.T) {
	relations := make(relationCollector)
	args := struct {
		person, session, account, role, service string
	}{
		person:  "idc#d-123#user-456",
		session: "idc#d-123#user-456|key#ASIA123#ARO123",
		account: "111111111111",
		role:    "arn:aws:iam::111111111111:role/reader",
		service: "s3.amazonaws.com",
	}

	recordEventRelations(
		relations,
		"test",
		"2026-07-24T11:00:00Z",
		args.person,
		args.session,
		args.account,
		args.role,
		args.service,
		[]string{"s3:bucket:logs"},
	)
	recordEventRelations(
		relations,
		"test",
		"2026-07-24T10:00:00Z",
		args.person,
		args.session,
		args.account,
		args.role,
		args.service,
		[]string{"s3:bucket:logs"},
	)

	// Six noun identities form 15 unordered pairs and 30 directed edges.
	if len(relations) != 30 {
		t.Fatalf("relation count = %d, want 30", len(relations))
	}

	for _, edge := range relations.edges() {
		inverse := ddblib.NewRelation(
			edge.CustomerID,
			edge.RelatedKind,
			edge.RelatedID,
			edge.SubjectKind,
			edge.SubjectID,
			edge.FirstSeen,
		)
		got, ok := relations[inverse.PK+"\x00"+inverse.SK]
		if !ok {
			t.Fatalf("missing inverse for %s %q to %s %q",
				edge.SubjectKind, edge.SubjectID, edge.RelatedKind, edge.RelatedID)
		}
		if got.FirstSeen != "2026-07-24T10:00:00Z" || got.LastSeen != "2026-07-24T11:00:00Z" {
			t.Fatalf("inverse bounds = %s/%s, want both observations", got.FirstSeen, got.LastSeen)
		}
	}
}

func TestRecordEventRelationsSkipsMissingIdentitiesAndResourcePairs(t *testing.T) {
	relations := make(relationCollector)
	recordEventRelations(
		relations,
		"test",
		"2026-07-24T10:00:00Z",
		"",
		"",
		"111111111111",
		"",
		"s3.amazonaws.com",
		[]string{"s3:bucket:one", "s3:bucket:two"},
	)

	// account-service plus each resource paired with account and service:
	// five unordered pairs, ten directed edges. Resources never pair together.
	if len(relations) != 10 {
		t.Fatalf("relation count = %d, want 10", len(relations))
	}
	for _, edge := range relations.edges() {
		if edge.SubjectKind == ddblib.RelationKindResource &&
			edge.RelatedKind == ddblib.RelationKindResource {
			t.Fatalf("unexpected resource-to-resource edge: %+v", edge)
		}
		if edge.SubjectID == "" || edge.RelatedID == "" {
			t.Fatalf("edge contains an empty identity: %+v", edge)
		}
	}
}

func TestRelationCollectorReplacesWindowedSessionRef(t *testing.T) {
	relations := make(relationCollector)
	oldRef := "iamuser#reader|win#ROLE#2026-07-24T10:10:00Z"
	newRef := "iamuser#reader|win#ROLE#2026-07-24T10:00:00Z"
	recordEventRelations(
		relations,
		"test",
		"2026-07-24T10:10:00Z",
		"iamuser#reader",
		oldRef,
		"111111111111",
		"",
		"",
		nil,
	)

	relations.replaceID(ddblib.RelationKindSession, oldRef, newRef)
	for _, edge := range relations.edges() {
		if edge.SubjectID == oldRef || edge.RelatedID == oldRef {
			t.Fatalf("old session ref remains in edge: %+v", edge)
		}
	}

	want := ddblib.NewRelation(
		"test",
		ddblib.RelationKindSession,
		newRef,
		ddblib.RelationKindAccount,
		"111111111111",
		"2026-07-24T10:10:00Z",
	)
	if _, ok := relations[want.PK+"\x00"+want.SK]; !ok {
		t.Fatalf("replacement session edge was not created")
	}
}
