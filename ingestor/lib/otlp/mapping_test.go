package otlp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	lambdaevents "github.com/aws/aws-lambda-go/events"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/engseclabs/trailtool/ingestor/lib/events"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

var (
	eventTime    = time.Date(2026, 10, 1, 10, 5, 0, 0, time.UTC)
	observedTime = time.Date(2026, 10, 1, 10, 5, 3, 0, time.UTC)
	testEnvelope = events.NewEnvelope("default", events.File{
		Key:       "AWSLogs/111111111111/CloudTrail/us-east-1/2026/10/01/f.json.gz",
		AccountID: "111111111111",
		Region:    "us-east-1",
	})
)

func trigger() *events.Record {
	return &events.Record{
		EventID:           "evt-1",
		Time:              "2026-10-01T10:00:00Z",
		Event:             "s3.amazonaws.com:PutBucketPolicy",
		RequestParameters: json.RawMessage(`{"bucketName":"logs"}`),
		Resources:         []events.Resource{{ARN: "arn:aws:s3:::logs", AccountID: "111111111111", Type: "AWS::S3::Bucket"}},
		SourceIP:          "203.0.113.7",
	}
}

func envelopeEvent(t *testing.T, detailType string, detail any) lambdaevents.EventBridgeEvent {
	t.Helper()
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	return lambdaevents.EventBridgeEvent{
		Version:    "0",
		ID:         "eb-id-1",
		DetailType: detailType,
		Source:     events.Source,
		AccountID:  "222222222222",
		Time:       eventTime,
		Region:     "us-west-2",
		Detail:     raw,
	}
}

func sessionActivity(denied int, writes int) *events.SessionActivity {
	act := &events.SessionActivity{
		Envelope: testEnvelope,
		Session: events.SessionInfo{
			Sid:        "gfo65rnbteswfydb",
			Person:     events.Person{Key: "idc#d-123#user-456", Email: "alice@example.com"},
			Type:       "cli",
			AccountID:  "111111111111",
			RoleARN:    "arn:aws:iam::111111111111:role/admin",
			NewSession: true,
			Origin:     events.Origin{SessionTags: map[string]string{"team": "platform"}},
		},
		Activity: events.Activity{
			Start:       "2026-10-01T10:00:00Z",
			End:         "2026-10-01T10:01:00Z",
			EventsCount: 3,
			DeniedCount: denied,
			EventCounts: map[string]int{"s3.amazonaws.com:GetObject": 2, "s3.amazonaws.com:PutBucketPolicy": 1},
			SourceIPs:   []string{"203.0.113.7"},
			Clients:     []types.ClientAggregate{{Key: "cli|aws-cli|2.17.0", Category: "cli", Name: "aws-cli", Version: "2.17.0", TotalEventCount: 3}},
			WriteCount:  writes,
			Writes:      []events.Record{},
		},
	}
	for i := range writes {
		w := *trigger()
		w.EventID = fmt.Sprintf("evt-%d", i)
		act.Activity.Writes = append(act.Activity.Writes, w)
	}
	return act
}

func attrMap(kvs []*commonv1.KeyValue) map[string]*commonv1.AnyValue {
	m := make(map[string]*commonv1.AnyValue, len(kvs))
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	return m
}

func mustAttr(t *testing.T, attrs map[string]*commonv1.AnyValue, key string) *commonv1.AnyValue {
	t.Helper()
	v, ok := attrs[key]
	if !ok {
		t.Fatalf("missing attribute %q", key)
	}
	return v
}

func TestBuildLogsEnvelope(t *testing.T) {
	ev := envelopeEvent(t, events.DetailTypeNounCreated, &events.NounCreated{
		Envelope: testEnvelope, Noun: events.NewNoun("account", "111111111111"), FirstSeen: "2026-10-01T10:00:00Z",
	})
	logs := BuildLogs(ev, Resource{ServiceName: "trailtool-prod", ScopeVersion: "1.4.0"}, observedTime)

	rl := logs.ResourceLogs[0]
	res := attrMap(rl.Resource.Attributes)
	for key, want := range map[string]string{
		"service.name":     "trailtool-prod",
		"cloud.provider":   "aws",
		"cloud.account.id": "222222222222",
		"cloud.region":     "us-west-2",
	} {
		if got := mustAttr(t, res, key).GetStringValue(); got != want {
			t.Errorf("resource %s = %q, want %q", key, got, want)
		}
	}
	scope := rl.ScopeLogs[0].Scope
	if scope.Name != "trailtool" || scope.Version != "1.4.0" {
		t.Errorf("scope = %s@%s, want trailtool@1.4.0", scope.Name, scope.Version)
	}

	rec := rl.ScopeLogs[0].LogRecords[0]
	if rec.TimeUnixNano != uint64(eventTime.UnixNano()) {
		t.Errorf("TimeUnixNano = %d, want event time %d", rec.TimeUnixNano, eventTime.UnixNano())
	}
	if rec.ObservedTimeUnixNano != uint64(observedTime.UnixNano()) {
		t.Errorf("ObservedTimeUnixNano = %d, want %d", rec.ObservedTimeUnixNano, observedTime.UnixNano())
	}
	attrs := attrMap(rec.Attributes)
	if got := mustAttr(t, attrs, "event.name").GetStringValue(); got != events.DetailTypeNounCreated {
		t.Errorf("event.name = %q", got)
	}
	if rec.EventName != events.DetailTypeNounCreated {
		t.Errorf("EventName = %q", rec.EventName)
	}
	if got := mustAttr(t, attrs, "trailtool.event_id").GetStringValue(); got != "eb-id-1" {
		t.Errorf("trailtool.event_id = %q", got)
	}

	// The payload must encode; LogsData is the OTLP/HTTP request body.
	if _, err := proto.Marshal(logs); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRecordZeroTimeLeavesTimeUnset(t *testing.T) {
	ev := envelopeEvent(t, events.DetailTypeNounCreated, &events.NounCreated{Envelope: testEnvelope, Noun: events.NewNoun("account", "1")})
	ev.Time = time.Time{}
	if rec := BuildRecord(ev, observedTime); rec.TimeUnixNano != 0 {
		t.Errorf("TimeUnixNano = %d, want 0 for an unknown time", rec.TimeUnixNano)
	}
}

func TestBuildRecordNounCreated(t *testing.T) {
	ev := envelopeEvent(t, events.DetailTypeNounCreated, &events.NounCreated{
		Envelope:  testEnvelope,
		Noun:      events.NewNoun("resource", "111111111111#czM6YnVja2V0OmxvZ3M"),
		FirstSeen: "2026-10-01T10:00:00Z",
		Trigger:   trigger(),
	})
	rec := BuildRecord(ev, observedTime)

	if rec.SeverityNumber != logsv1.SeverityNumber_SEVERITY_NUMBER_INFO || rec.SeverityText != "INFO" {
		t.Errorf("severity = %v/%s, want INFO", rec.SeverityNumber, rec.SeverityText)
	}
	if got, want := rec.Body.GetStringValue(), "resource s3:bucket:logs in account 111111111111 seen for the first time"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	attrs := attrMap(rec.Attributes)
	for key, want := range map[string]string{
		"trailtool.kind":          "resource",
		"trailtool.identifier":    "s3:bucket:logs",
		"trailtool.file.key":      testEnvelope.File.Key,
		"trailtool.customer_id":   "default",
		"trailtool.trigger.event": "s3.amazonaws.com:PutBucketPolicy",
	} {
		if got := mustAttr(t, attrs, key).GetStringValue(); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := mustAttr(t, attrs, "trailtool.schema_version").GetIntValue(); got != 1 {
		t.Errorf("schema_version = %d, want int 1", got)
	}
	// request_parameters keys are data, so they stay one map value.
	params := mustAttr(t, attrs, "trailtool.trigger.request_parameters").GetKvlistValue()
	if params == nil || params.Values[0].Key != "bucketName" || params.Values[0].Value.GetStringValue() != "logs" {
		t.Errorf("request_parameters = %v, want kvlist {bucketName: logs}", params)
	}
	if _, ok := attrs["trailtool.trigger.request_parameters.bucketName"]; ok {
		t.Error("request_parameters was flattened into per-key attributes")
	}
	// Arrays stay arrays, with objects as kvlists.
	resources := mustAttr(t, attrs, "trailtool.trigger.resources").GetArrayValue()
	if resources == nil || len(resources.Values) != 1 || resources.Values[0].GetKvlistValue() == nil {
		t.Errorf("trigger.resources = %v, want array of one kvlist", resources)
	}
}

func TestBuildRecordRelationCreated(t *testing.T) {
	ev := envelopeEvent(t, events.DetailTypeRelationCreated, &events.RelationCreated{
		Envelope:      testEnvelope,
		Subject:       events.NewNoun("person", "alice@example.com"),
		Related:       events.NewNoun("account", "123456789012"),
		FirstSeen:     "2026-10-01T10:00:00Z",
		SubjectCounts: map[string]int{"accounts": 1, "sessions": 9},
		Trigger:       trigger(),
	})
	rec := BuildRecord(ev, observedTime)

	if got, want := rec.Body.GetStringValue(), "person alice@example.com reached account 123456789012 for the first time"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if rec.SeverityText != "INFO" {
		t.Errorf("severity = %s, want INFO", rec.SeverityText)
	}
	attrs := attrMap(rec.Attributes)
	if got := mustAttr(t, attrs, "trailtool.subject.kind").GetStringValue(); got != "person" {
		t.Errorf("subject.kind = %q", got)
	}
	if got := mustAttr(t, attrs, "trailtool.related.id").GetStringValue(); got != "123456789012" {
		t.Errorf("related.id = %q", got)
	}
	counts := mustAttr(t, attrs, "trailtool.subject_counts").GetKvlistValue()
	if counts == nil || len(counts.Values) != 2 || counts.Values[0].Key != "accounts" || counts.Values[0].Value.GetIntValue() != 1 {
		t.Errorf("subject_counts = %v, want kvlist of ints", counts)
	}
}

func TestBuildRecordSessionActivity(t *testing.T) {
	ev := envelopeEvent(t, events.DetailTypeSessionActivity, sessionActivity(0, 2))
	rec := BuildRecord(ev, observedTime)

	if rec.SeverityNumber != logsv1.SeverityNumber_SEVERITY_NUMBER_INFO {
		t.Errorf("severity = %v, want INFO with no denied calls", rec.SeverityNumber)
	}
	want := "alice@example.com: s3.amazonaws.com:GetObject ×2, s3.amazonaws.com:PutBucketPolicy ×1; 0 denied, 2 writes in account 111111111111 (new cli session gfo65rnbteswfydb; this file)"
	if got := rec.Body.GetStringValue(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	attrs := attrMap(rec.Attributes)
	if got := mustAttr(t, attrs, "trailtool.session.person.email").GetStringValue(); got != "alice@example.com" {
		t.Errorf("session.person.email = %q", got)
	}
	if got := mustAttr(t, attrs, "trailtool.session.new_session").GetBoolValue(); !got {
		t.Error("session.new_session = false, want true")
	}
	if got := mustAttr(t, attrs, "trailtool.activity.write_count").GetIntValue(); got != 2 {
		t.Errorf("activity.write_count = %d, want 2", got)
	}
	writes := mustAttr(t, attrs, "trailtool.activity.writes").GetArrayValue()
	if writes == nil || len(writes.Values) != 2 {
		t.Fatalf("activity.writes = %v, want array of 2", writes)
	}
	first := attrMap(writes.Values[0].GetKvlistValue().GetValues())
	if got := mustAttr(t, first, "event_id").GetStringValue(); got != "evt-0" {
		t.Errorf("writes[0].event_id = %q", got)
	}
	ips := mustAttr(t, attrs, "trailtool.activity.source_ips").GetArrayValue()
	if ips == nil || ips.Values[0].GetStringValue() != "203.0.113.7" {
		t.Errorf("activity.source_ips = %v, want string array", ips)
	}
	if mustAttr(t, attrs, "trailtool.activity.event_counts").GetKvlistValue() == nil {
		t.Error("activity.event_counts is not a kvlist")
	}
	if mustAttr(t, attrs, "trailtool.session.origin.session_tags").GetKvlistValue() == nil {
		t.Error("session.origin.session_tags is not a kvlist")
	}
	for key := range attrs {
		if strings.HasPrefix(key, "trailtool.activity.event_counts.") {
			t.Errorf("event_counts flattened into %q", key)
		}
		if strings.HasSuffix(key, "_dropped") {
			t.Errorf("unexpected %s on a small record", key)
		}
	}
}

func TestBuildRecordSessionActivityDeniedIsWarn(t *testing.T) {
	ev := envelopeEvent(t, events.DetailTypeSessionActivity, sessionActivity(1, 0))
	rec := BuildRecord(ev, observedTime)
	if rec.SeverityNumber != logsv1.SeverityNumber_SEVERITY_NUMBER_WARN || rec.SeverityText != "WARN" {
		t.Errorf("severity = %v/%s, want WARN", rec.SeverityNumber, rec.SeverityText)
	}
}

func TestBuildRecordUnknownDetailType(t *testing.T) {
	ev := envelopeEvent(t, "TrailTool Something New", map[string]any{"schema_version": 1, "thing": "x"})
	rec := BuildRecord(ev, observedTime)
	if rec.Body.GetStringValue() != "TrailTool Something New" || rec.SeverityText != "INFO" {
		t.Errorf("body/severity = %q/%s, want detail-type and INFO", rec.Body.GetStringValue(), rec.SeverityText)
	}
	if got := mustAttr(t, attrMap(rec.Attributes), "trailtool.thing").GetStringValue(); got != "x" {
		t.Errorf("trailtool.thing = %q", got)
	}
}

func TestBuildRecordCapsArrays(t *testing.T) {
	ev := envelopeEvent(t, events.DetailTypeSessionActivity, sessionActivity(0, 40))
	rec := BuildRecord(ev, observedTime)
	attrs := attrMap(rec.Attributes)

	writes := mustAttr(t, attrs, "trailtool.activity.writes").GetArrayValue()
	if len(writes.Values) != MaxArrayItems {
		t.Errorf("writes = %d items, want %d", len(writes.Values), MaxArrayItems)
	}
	if got := mustAttr(t, attrs, "trailtool.activity.writes_dropped").GetIntValue(); got != 40-MaxArrayItems {
		t.Errorf("writes_dropped = %d, want %d", got, 40-MaxArrayItems)
	}
	// Earliest writes are kept.
	if got := attrMap(writes.Values[0].GetKvlistValue().GetValues())["event_id"].GetStringValue(); got != "evt-0" {
		t.Errorf("first kept write = %q, want evt-0", got)
	}
}

func TestBuildRecordTruncatesStrings(t *testing.T) {
	act := sessionActivity(0, 0)
	act.Session.RoleSessionName = strings.Repeat("é", MaxStringBytes) // 2 bytes per rune
	rec := BuildRecord(envelopeEvent(t, events.DetailTypeSessionActivity, act), observedTime)

	got := mustAttr(t, attrMap(rec.Attributes), "trailtool.session.role_session_name").GetStringValue()
	if len(got) != MaxStringBytes {
		t.Errorf("role_session_name = %d bytes, want %d", len(got), MaxStringBytes)
	}
	if !strings.HasSuffix(got, "é") {
		t.Error("truncation split a rune")
	}
}

func TestBuildRecordFitsSizeBudget(t *testing.T) {
	act := sessionActivity(0, MaxArrayItems)
	big := `{"policy":"` + strings.Repeat("x", 1900) + `"}`
	for i := range act.Activity.Writes {
		act.Activity.Writes[i].RequestParameters = json.RawMessage(big)
		act.Activity.Writes[i].ErrorMessage = strings.Repeat("y", 500)
		act.Activity.Writes[i].UserAgent = strings.Repeat("z", 1000)
	}
	act.Activity.WriteCount = MaxArrayItems
	rec := BuildRecord(envelopeEvent(t, events.DetailTypeSessionActivity, act), observedTime)

	if size := proto.Size(rec); size > MaxRecordBytes {
		t.Errorf("record = %d bytes, want <= %d", size, MaxRecordBytes)
	}
	attrs := attrMap(rec.Attributes)
	kept := len(mustAttr(t, attrs, "trailtool.activity.writes").GetArrayValue().Values)
	dropped := mustAttr(t, attrs, "trailtool.activity.writes_dropped").GetIntValue()
	if kept == 0 || kept+int(dropped) != MaxArrayItems {
		t.Errorf("kept %d + dropped %d, want a nonzero split of %d", kept, dropped, MaxArrayItems)
	}
}

func TestBuildRecordCapsMapFields(t *testing.T) {
	act := sessionActivity(0, 0)
	act.Activity.EventCounts = map[string]int{}
	for i := range MaxMapEntries + 7 {
		act.Activity.EventCounts[fmt.Sprintf("svc.amazonaws.com:Call%03d", i)] = 1
	}
	attrs := attrMap(BuildRecord(envelopeEvent(t, events.DetailTypeSessionActivity, act), observedTime).Attributes)

	counts := mustAttr(t, attrs, "trailtool.activity.event_counts").GetKvlistValue()
	if len(counts.Values) != MaxMapEntries {
		t.Errorf("event_counts = %d entries, want %d", len(counts.Values), MaxMapEntries)
	}
	if got := mustAttr(t, attrs, "trailtool.activity.event_counts_dropped").GetIntValue(); got != 7 {
		t.Errorf("event_counts_dropped = %d, want 7", got)
	}
}

func TestSessionSummary(t *testing.T) {
	base := func() events.SessionActivity {
		return events.SessionActivity{
			Session: events.SessionInfo{
				Sid:             "example-session-id",
				Person:          events.Person{Key: "idc#d-0000000000#user-0000"},
				Type:            "web",
				AccountID:       "111111111111",
				RoleARN:         "arn:aws:iam::111111111111:role/ExampleRole",
				RoleSessionName: "example-user",
			},
			Activity: events.Activity{
				EventsCount: 1,
				EventCounts: map[string]int{"logs.amazonaws.com:DescribeMetricFilters": 1},
			},
		}
	}
	const tail = "in account 111111111111 (web session example-session-id; this file)"

	tests := []struct {
		name   string
		modify func(*events.SessionActivity)
		want   string
	}{
		{
			name:   "single read-only action",
			modify: func(*events.SessionActivity) {},
			want:   "example-user: logs.amazonaws.com:DescribeMetricFilters ×1; 0 denied, 0 writes " + tail,
		},
		{
			name: "multiple actions ordered by count then name",
			modify: func(d *events.SessionActivity) {
				d.Activity.EventCounts = map[string]int{
					"s3.amazonaws.com:ListBuckets":   1,
					"ec2.amazonaws.com:RunInstances": 1,
					"s3.amazonaws.com:GetObject":     4,
					"iam.amazonaws.com:CreateRole":   2,
				}
				d.Activity.DeniedEventCounts = map[string]int{"iam.amazonaws.com:CreateRole": 2}
				d.Activity.DeniedCount = 2
				d.Activity.WriteCount = 5
			},
			want: "example-user: s3.amazonaws.com:GetObject ×4, iam.amazonaws.com:CreateRole ×2, " +
				"denied iam.amazonaws.com:CreateRole ×2, ec2.amazonaws.com:RunInstances ×1, " +
				"s3.amazonaws.com:ListBuckets ×1; 2 denied, 5 writes " + tail,
		},
		{
			name: "denied only",
			modify: func(d *events.SessionActivity) {
				d.Activity.EventCounts = map[string]int{}
				d.Activity.DeniedEventCounts = map[string]int{"s3.amazonaws.com:GetObject": 3}
				d.Activity.DeniedCount = 3
				d.Activity.WriteCount = 3
			},
			want: "example-user: denied s3.amazonaws.com:GetObject ×3; 3 denied, 3 writes " + tail,
		},
		{
			name: "empty action maps",
			modify: func(d *events.SessionActivity) {
				d.Activity.EventCounts = nil
				d.Activity.DeniedEventCounts = nil
			},
			want: "example-user: no actions recorded; 0 denied, 0 writes " + tail,
		},
		{
			name: "truncation",
			modify: func(d *events.SessionActivity) {
				d.Activity.EventCounts = map[string]int{}
				for i := range MaxSummaryActions + 3 {
					d.Activity.EventCounts[fmt.Sprintf("svc.amazonaws.com:Call%d", i)] = 10 - i
				}
			},
			want: "example-user: svc.amazonaws.com:Call0 ×10, svc.amazonaws.com:Call1 ×9, " +
				"svc.amazonaws.com:Call2 ×8, svc.amazonaws.com:Call3 ×7, svc.amazonaws.com:Call4 ×6, " +
				"+3 more action types; 0 denied, 0 writes " + tail,
		},
		{
			name: "new session",
			modify: func(d *events.SessionActivity) {
				d.Session.NewSession = true
			},
			want: "example-user: logs.amazonaws.com:DescribeMetricFilters ×1; 0 denied, 0 writes " +
				"in account 111111111111 (new web session example-session-id; this file)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := base()
			tt.modify(&d)
			if got := sessionSummary(d); got != tt.want {
				t.Errorf("summary =\n  %q\nwant\n  %q", got, tt.want)
			}
		})
	}
}

func TestSessionSummaryActorFallback(t *testing.T) {
	full := events.SessionInfo{
		Sid:             "example-session-id",
		Person:          events.Person{Key: "idc#d-0000000000#user-0000", Email: "user@example.com", Label: "Example User"},
		RoleSessionName: "example-user",
		RoleARN:         "arn:aws:iam::111111111111:role/ExampleRole",
	}
	tests := []struct {
		name  string
		clear func(*events.SessionInfo)
		want  string
	}{
		{"email", func(*events.SessionInfo) {}, "user@example.com"},
		{"display name", func(s *events.SessionInfo) { s.Person.Email = "" }, "Example User"},
		{"role session name", func(s *events.SessionInfo) { s.Person.Email, s.Person.Label = "", "" }, "example-user"},
		{"role ARN when role session name is absent", func(s *events.SessionInfo) {
			s.Person.Email, s.Person.Label, s.RoleSessionName = "", "", ""
		}, "arn:aws:iam::111111111111:role/ExampleRole"},
		{"person key", func(s *events.SessionInfo) {
			s.Person.Email, s.Person.Label, s.RoleSessionName, s.RoleARN = "", "", "", ""
		}, "idc#d-0000000000#user-0000"},
		{"session ID", func(s *events.SessionInfo) {
			s.Person = events.Person{}
			s.RoleSessionName, s.RoleARN = "", ""
		}, "example-session-id"},
		{"unknown actor", func(s *events.SessionInfo) { *s = events.SessionInfo{} }, "Unknown actor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := full
			tt.clear(&s)
			d := events.SessionActivity{
				Session:  s,
				Activity: events.Activity{EventCounts: map[string]int{"logs.amazonaws.com:DescribeMetricFilters": 1}},
			}
			got := sessionSummary(d)
			if !strings.HasPrefix(got, tt.want+": logs.amazonaws.com:DescribeMetricFilters ×1; ") {
				t.Errorf("summary = %q, want actor %q followed by the action", got, tt.want)
			}
		})
	}
}
