package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"

	"github.com/engseclabs/trailtool/ingestor/lib/aggregator"
	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

var update = flag.Bool("update", false, "rewrite golden files")

func init() { emitBaseDelay = 0 }

const (
	testPerson = "idc#d-123#user-456"
	testRole   = "arn:aws:iam::111111111111:role/admin"
)

var testEnv = NewEnvelope("default", File{
	Key:       "AWSLogs/111111111111/CloudTrail/us-east-1/2026/10/01/111111111111_CloudTrail_us-east-1_20261001T1005Z_abc.json.gz",
	AccountID: "111111111111",
	Region:    "us-east-1",
})

func boolPtr(b bool) *bool { return &b }

func putBucketPolicy() types.CloudTrailRecord {
	return types.CloudTrailRecord{
		EventID:         "evt-1",
		EventTime:       "2026-10-01T10:00:00Z",
		EventSource:     "s3.amazonaws.com",
		EventName:       "PutBucketPolicy",
		ReadOnly:        boolPtr(false),
		SourceIPAddress: "203.0.113.7",
		UserAgent:       "aws-cli/2.17.0",
		RequestParameters: map[string]any{
			"bucketName": "logs",
		},
		ResponseElements: map[string]any{"secret": "never emitted"},
		Resources:        []types.CloudTrailResource{{ARN: "arn:aws:s3:::logs", AccountID: "111111111111", Type: "AWS::S3::Bucket"}},
	}
}

func deniedGetObject() types.CloudTrailRecord {
	return types.CloudTrailRecord{
		EventID:         "evt-2",
		EventTime:       "2026-10-01T10:01:00Z",
		EventSource:     "s3.amazonaws.com",
		EventName:       "GetObject",
		ReadOnly:        boolPtr(true),
		ErrorCode:       "AccessDenied",
		ErrorMessage:    "User is not authorized to perform s3:GetObject",
		SourceIPAddress: "203.0.113.7",
		UserIdentity:    types.UserIdentity{InvokedBy: "cloudformation.amazonaws.com"},
	}
}

func testResult() *aggregator.Result {
	edge := func(subjectKind, subjectID, relatedKind, relatedID string, subjectNew bool) aggregator.NewEdge {
		return aggregator.NewEdge{
			DynamoDBRelation: ddblib.NewRelation("default", subjectKind, subjectID, relatedKind, relatedID, "2026-10-01T10:00:00Z"),
			SubjectNew:       subjectNew,
			TriggerEventID:   "evt-1",
		}
	}
	parentRef := identity.SessionRef(testPerson, "sis#arn:aws:signin::111111111111:session/parent#AROAPARENT")
	childRef := identity.SessionRef(testPerson, "key#ASIACHILD#AROACHILD")
	return &aggregator.Result{
		Namespace: "default",
		NewNouns: []aggregator.NewNoun{
			{Kind: ddblib.RelationKindPerson, ID: testPerson, FirstSeen: "2026-10-01T10:00:00Z", TriggerEventID: "evt-1"},
			{Kind: ddblib.RelationKindSession, ID: childRef, FirstSeen: "2026-10-01T10:00:00Z", TriggerEventID: "evt-1"},
		},
		NewEdges: []aggregator.NewEdge{
			edge(ddblib.RelationKindPerson, testPerson, ddblib.RelationKindService, "s3.amazonaws.com", true),
			edge(ddblib.RelationKindPerson, testPerson, ddblib.RelationKindSession, childRef, true),
			edge(ddblib.RelationKindService, "s3.amazonaws.com", ddblib.RelationKindPerson, testPerson, false),
			edge(ddblib.RelationKindRole, testRole, ddblib.RelationKindResource, "s3:bucket:logs", false),
			edge(ddblib.RelationKindRole, testRole, ddblib.RelationKindService, "s3.amazonaws.com", false),
		},
		Records: map[string]types.CloudTrailRecord{"evt-1": putBucketPolicy()},
		Sessions: []aggregator.SessionResult{{
			Sid: identity.SidFromRef(childRef),
			SK:  "key#ASIACHILD#AROACHILD",
			New: true,
			Session: &types.DynamoDBSession{
				PersonKey:               testPerson,
				SessionType:             "cli",
				AccountID:               "111111111111",
				RoleARN:                 testRole,
				RoleSessionName:         "alice",
				StartTime:               "2026-10-01T10:00:00Z",
				EndTime:                 "2026-10-01T10:01:00Z",
				EventsCount:             3,
				DeniedEventCount:        1,
				ServiceDrivenEventCount: 1,
				EventCounts:             map[string]int{"s3.amazonaws.com:PutBucketPolicy": 1, "s3.amazonaws.com:GetObject": 2},
				DeniedEventCounts:       map[string]int{"s3.amazonaws.com:GetObject": 1},
				SourceIPs:               []string{"203.0.113.7"},
				Clients:                 []types.ClientAggregate{{Key: "cli|aws-cli|2.17.0||||", Category: "cli", Name: "aws-cli", Version: "2.17.0", TotalEventCount: 3}},
				AssumedFromSession:      parentRef,
				AssumedFromRoleARN:      "arn:aws:iam::111111111111:role/base",
				SessionTags:             map[string]string{"team": "platform"},
			},
			Person: &types.DynamoDBPerson{PersonKey: testPerson, Email: "alice@example.com", DisplayName: "Alice Example"},
			Writes: []types.CloudTrailRecord{putBucketPolicy(), deniedGetObject()},
		}},
	}
}

// fakeCounts returns post-write summary counts for every subject PK.
func fakeCounts(post map[string]map[string]int, reads *int) CountsFunc {
	return func(_ context.Context, pk string) (map[string]int, error) {
		*reads++
		return post[pk], nil
	}
}

func assertGolden(t *testing.T, name string, detail any) {
	t.Helper()
	got, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch (run with -update to accept)\n got: %s\nwant: %s", name, got, want)
	}
}

func TestGoldenDetails(t *testing.T) {
	res := testResult()
	rolePK := ddblib.RelationPK("default", ddblib.RelationKindRole, testRole)
	reads := 0
	counts := fakeCounts(map[string]map[string]int{
		// Post-write: the batch added a service and a resource edge.
		rolePK: {"people": 4, "sessions": 9, "accounts": 1, "roles": 0, "services": 3, "resources": 6},
	}, &reads)

	created := BuildCreated(context.Background(), testEnv, res, counts)
	byType := map[string][]Event{}
	for _, ev := range created {
		byType[ev.DetailType] = append(byType[ev.DetailType], ev)
	}

	if n := len(byType[DetailTypeNounCreated]); n != 1 {
		t.Fatalf("noun events = %d, want 1 (sessions never emit)", n)
	}
	assertGolden(t, "noun_created", byType[DetailTypeNounCreated][0].Detail)

	// person→service and the two role edges emit; person→session and the
	// service→person inverse do not.
	relations := byType[DetailTypeRelationCreated]
	if len(relations) != 3 {
		t.Fatalf("relation events = %d, want 3", len(relations))
	}
	for _, ev := range relations {
		rc := ev.Detail.(*RelationCreated)
		if rc.Subject.Kind == ddblib.RelationKindSession || rc.Related.Kind == ddblib.RelationKindSession {
			t.Fatalf("session relation emitted: %+v", rc)
		}
	}
	if reads != 1 {
		t.Fatalf("summary reads = %d, want 1 (the role, once; the new person reads nothing)", reads)
	}
	personEdge := relations[0].Detail.(*RelationCreated)
	for name, n := range personEdge.SubjectCounts {
		if n != 0 {
			t.Fatalf("new subject count %s = %d, want all zero", name, n)
		}
	}
	roleEdge := relations[1].Detail.(*RelationCreated)
	if roleEdge.SubjectCounts["services"] != 2 || roleEdge.SubjectCounts["resources"] != 5 || roleEdge.SubjectCounts["people"] != 4 {
		t.Fatalf("role counts = %v, want post-write minus this batch's edges", roleEdge.SubjectCounts)
	}
	assertGolden(t, "relation_created", roleEdge)

	activity := BuildSessionActivity(testEnv, res)
	if len(activity) != 1 {
		t.Fatalf("session events = %d, want 1", len(activity))
	}
	assertGolden(t, "session_activity", activity[0].Detail)
}

func TestBuildCreatedWithoutCountsOmitsThemForExistingSubjects(t *testing.T) {
	for _, ev := range BuildCreated(context.Background(), testEnv, testResult(), nil) {
		rc, ok := ev.Detail.(*RelationCreated)
		if ok && rc.Subject.Kind == ddblib.RelationKindRole && rc.SubjectCounts != nil {
			t.Fatalf("role counts = %v without a reader, want nil", rc.SubjectCounts)
		}
	}
}

func TestTrimBoundsLargeFields(t *testing.T) {
	big := map[string]any{"policy": strings.Repeat("x", 3000)}
	msg := strings.Repeat("é", 600)
	trimmed := Trim(types.CloudTrailRecord{RequestParameters: big, ErrorMessage: msg, ResponseElements: big})

	var params map[string]any
	if err := json.Unmarshal(trimmed.RequestParameters, &params); err != nil {
		t.Fatalf("request_parameters: %v", err)
	}
	if params["_truncated"] != true || params["bytes"].(float64) <= maxRequestParamBytes {
		t.Fatalf("request_parameters = %v, want a truncation stub with the original size", params)
	}
	if got := []rune(trimmed.ErrorMessage); len(got) != maxErrorMessageChars {
		t.Fatalf("error_message has %d chars, want %d", len(got), maxErrorMessageChars)
	}
	raw, _ := json.Marshal(trimmed)
	if strings.Contains(string(raw), "response") {
		t.Fatalf("trimmed record leaks responseElements: %s", raw)
	}
}

func TestBuildSessionActivityCapsWrites(t *testing.T) {
	res := testResult()
	writes := make([]types.CloudTrailRecord, MaxWrites+7)
	for i := range writes {
		writes[i] = putBucketPolicy()
	}
	res.Sessions[0].Writes = writes

	a := BuildSessionActivity(testEnv, res)[0].Detail.(*SessionActivity).Activity
	if len(a.Writes) != MaxWrites || a.WritesTruncated != 7 || a.WriteCount != MaxWrites+7 {
		t.Fatalf("writes=%d truncated=%d count=%d, want %d/7/%d", len(a.Writes), a.WritesTruncated, a.WriteCount, MaxWrites, MaxWrites+7)
	}
}

func TestBuildEntryShedsWritesToFit(t *testing.T) {
	res := testResult()
	writes := make([]types.CloudTrailRecord, MaxWrites)
	for i := range writes {
		w := putBucketPolicy()
		// Just under the request_parameters cap, so trimming keeps them whole.
		w.RequestParameters = map[string]any{"p": strings.Repeat("y", maxRequestParamBytes-20)}
		w.ErrorMessage = strings.Repeat("z", maxErrorMessageChars)
		w.UserAgent = strings.Repeat("u", 3000)
		writes[i] = w
	}
	res.Sessions[0].Writes = writes
	ev := BuildSessionActivity(testEnv, res)[0]

	entry, ok := buildEntry("arn:aws:events:us-east-1:111111111111:event-bus/default", ev)
	if !ok {
		t.Fatalf("entry dropped, want it shrunk to fit")
	}
	if size := entrySize(ev.DetailType, []byte(aws.ToString(entry.Detail))); size > maxEntryBytes {
		t.Fatalf("entry is %d bytes, over the %d limit", size, maxEntryBytes)
	}
	a := ev.Detail.(*SessionActivity).Activity
	if len(a.Writes) >= MaxWrites || a.WritesTruncated != MaxWrites-len(a.Writes) {
		t.Fatalf("writes=%d truncated=%d, want writes shed and counted", len(a.Writes), a.WritesTruncated)
	}
}

// fakePublisher records PutEvents calls and fails entries on demand.
type fakePublisher struct {
	calls     [][]ebtypes.PutEventsRequestEntry
	err       error
	failFirst int // entries to reject on the first call
}

func (p *fakePublisher) PutEvents(_ context.Context, in *eventbridge.PutEventsInput, _ ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error) {
	p.calls = append(p.calls, in.Entries)
	if p.err != nil {
		return nil, p.err
	}
	out := &eventbridge.PutEventsOutput{Entries: make([]ebtypes.PutEventsResultEntry, len(in.Entries))}
	if len(p.calls) == 1 {
		for i := 0; i < p.failFirst && i < len(in.Entries); i++ {
			out.Entries[i] = ebtypes.PutEventsResultEntry{ErrorCode: aws.String("ThrottlingException"), ErrorMessage: aws.String("slow down")}
			out.FailedEntryCount++
		}
	}
	return out, nil
}

func nounEvents(n int) []Event {
	evs := make([]Event, n)
	for i := range evs {
		evs[i] = Event{DetailType: DetailTypeNounCreated, Detail: &NounCreated{Envelope: testEnv, Kind: "service", ID: "s3.amazonaws.com"}}
	}
	return evs
}

func TestEmitBatchesByTenAndRetriesFailedEntries(t *testing.T) {
	pub := &fakePublisher{failFirst: 2}
	Emit(context.Background(), pub, "arn:aws:events:us-east-1:111111111111:event-bus/default", nounEvents(23))

	// 10 + 10 + 3, plus one retry of the first batch's 2 rejected entries.
	sizes := []int{}
	for _, call := range pub.calls {
		sizes = append(sizes, len(call))
	}
	want := []int{10, 2, 10, 3}
	if len(sizes) != len(want) {
		t.Fatalf("call sizes = %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("call sizes = %v, want %v", sizes, want)
		}
	}
	entry := pub.calls[0][0]
	if aws.ToString(entry.Source) != Source || aws.ToString(entry.EventBusName) == "" {
		t.Fatalf("entry = %+v, want trailtool source on the configured bus", entry)
	}
}

func TestEmitSwallowsPublisherErrors(t *testing.T) {
	pub := &fakePublisher{err: errors.New("bus unreachable")}
	Emit(context.Background(), pub, "arn:aws:events:us-east-1:111111111111:event-bus/default", nounEvents(3))
	// The SDK retries retryable call errors itself, so each batch is tried once.
	if len(pub.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(pub.calls))
	}
}

func TestEmitWithoutBusIsANoOp(t *testing.T) {
	pub := &fakePublisher{}
	Emit(context.Background(), pub, "", nounEvents(3))
	if len(pub.calls) != 0 {
		t.Fatalf("publisher called %d times with no bus configured", len(pub.calls))
	}
}

func TestPackBatchesRespectsRequestSize(t *testing.T) {
	detail := strings.Repeat("d", 100*1024)
	entries := make([]ebtypes.PutEventsRequestEntry, 5)
	for i := range entries {
		entries[i] = ebtypes.PutEventsRequestEntry{DetailType: aws.String(DetailTypeSessionActivity), Detail: aws.String(detail)}
	}
	batches := packBatches(entries)
	if len(batches) != 3 {
		t.Fatalf("batches = %d, want 3 (two ~100 KB entries per 256 KB request)", len(batches))
	}
}
