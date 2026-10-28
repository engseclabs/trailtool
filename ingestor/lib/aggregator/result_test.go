package aggregator

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// windowStore serves a fixed set of existing win# sessions to the adjacent
// window query and accepts every write.
type windowStore struct {
	existing []types.DynamoDBSession
}

func (s *windowStore) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return &dynamodb.GetItemOutput{}, nil
}

func (s *windowStore) Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	out := &dynamodb.QueryOutput{}
	for _, sess := range s.existing {
		item, err := attributevalue.MarshalMap(sess)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

func (s *windowStore) PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return &dynamodb.PutItemOutput{}, nil
}

func (s *windowStore) TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

var _ ddblib.SessionStore = (*windowStore)(nil)

func TestWriteSessionRecordReportsFoldSurvivor(t *testing.T) {
	const person = "iamuser#arn:aws:iam::111111111111:user/deploy-bot"
	earlier := types.DynamoDBSession{
		PK: "test#" + person, SK: "win#AIDAEXAMPLE#2026-07-15T10:00:00Z", PersonKey: person,
		SessionType: SessionTypeCLI, StartTime: "2026-07-15T10:00:00Z", EndTime: "2026-07-15T10:10:00Z",
		EventsCount: 2, Version: 3,
	}
	incoming := &types.DynamoDBSession{
		PK: earlier.PK, SK: "win#AIDAEXAMPLE#2026-07-15T10:20:00Z", PersonKey: person, RoleID: "AIDAEXAMPLE",
		SessionType: SessionTypeCLI, StartTime: "2026-07-15T10:20:00Z", EndTime: "2026-07-15T10:25:00Z",
		EventsCount: 1,
	}
	cfg := Config{Tables: Tables{Sessions: "sessions"}}

	got, err := writeSessionRecord(context.Background(), &windowStore{existing: []types.DynamoDBSession{earlier}}, cfg, incoming)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if got.SK != earlier.SK || got.Sid != identity.Sid(person, earlier.SK) {
		t.Fatalf("survivor = %s/%s, want the earlier window %s", got.SK, got.Sid, earlier.SK)
	}
	if got.New {
		t.Fatalf("fold into an existing window reported a new session")
	}
	if got.Session.EventsCount != 1 {
		t.Fatalf("result carries %d events, want only this batch's 1", got.Session.EventsCount)
	}

	fresh, err := writeSessionRecord(context.Background(), &windowStore{}, cfg, incoming)
	if err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	if !fresh.New || fresh.SK != incoming.SK {
		t.Fatalf("fresh window = %+v, want a new session under its own key", fresh)
	}
}

func TestIsWriteOrDenied(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		readOnly *bool
		errCode  string
		want     bool
	}{
		{"read", &yes, "", false},
		{"write", &no, "", true},
		{"readOnly absent", nil, "", true},
		{"denied read", &yes, "AccessDenied", true},
		{"failed read, not denied", &yes, "NoSuchBucket", false},
	}
	for _, tc := range cases {
		got := isWriteOrDenied(types.CloudTrailRecord{ReadOnly: tc.readOnly, ErrorCode: tc.errCode})
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCollectCreatedTakesEarliestObservation(t *testing.T) {
	relations := make(relationCollector)
	person := "idc#d-123#user-456"
	for _, obs := range []struct{ at, id, service string }{
		{"2026-07-24T10:05:00Z", "evt-late", "s3.amazonaws.com"},
		{"2026-07-24T10:00:00Z", "evt-early", "ec2.amazonaws.com"},
	} {
		recordEventRelations(relations, "test", obs.at, obs.id, person, "", "111111111111", "", obs.service, nil)
	}

	personPK := ddblib.RelationPK("test", ddblib.RelationKindPerson, person)
	toS3 := ddblib.NewRelation("test", ddblib.RelationKindPerson, person, ddblib.RelationKindService, "s3.amazonaws.com", "2026-07-24T10:05:00Z")
	res := &Result{}
	collectCreated(res, relations, map[string]bool{personPK: true}, []types.DynamoDBRelation{toS3})

	if len(res.NewNouns) != 1 {
		t.Fatalf("new nouns = %+v, want only the person", res.NewNouns)
	}
	noun := res.NewNouns[0]
	if noun.Kind != ddblib.RelationKindPerson || noun.ID != person || noun.FirstSeen != "2026-07-24T10:00:00Z" || noun.TriggerEventID != "evt-early" {
		t.Fatalf("noun = %+v, want the person first seen at evt-early", noun)
	}
	if len(res.NewEdges) != 1 || res.NewEdges[0].TriggerEventID != "evt-late" || !res.NewEdges[0].SubjectNew {
		t.Fatalf("edges = %+v, want the s3 edge triggered by evt-late on a new subject", res.NewEdges)
	}

	indexTriggers(res, []identity.Group{{Events: []types.CloudTrailRecord{{EventID: "evt-early"}, {EventID: "evt-late"}, {EventID: "evt-other"}}}})
	if len(res.Records) != 2 {
		t.Fatalf("indexed %d records, want only the 2 triggers", len(res.Records))
	}
}
