package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/eventbridge"

	"github.com/engseclabs/trailtool/ingestor/lib/aggregator"
	tevents "github.com/engseclabs/trailtool/ingestor/lib/events"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

type countingPublisher struct {
	calls int
	err   error
}

func (p *countingPublisher) PutEvents(context.Context, *eventbridge.PutEventsInput, ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return &eventbridge.PutEventsOutput{}, nil
}

func resultWithNoun() *aggregator.Result {
	return &aggregator.Result{
		Namespace: "default",
		NewNouns:  []aggregator.NewNoun{{Kind: "service", ID: "s3.amazonaws.com", FirstSeen: "2026-10-01T10:00:00Z"}},
		Sessions:  []aggregator.SessionResult{{Sid: "abc", Session: &types.DynamoDBSession{PersonKey: "p"}}},
	}
}

const testBus = "arn:aws:events:us-east-1:111111111111:event-bus/default"

func TestEmitChangeEventsRequiresBusAndPublisher(t *testing.T) {
	pub := &countingPublisher{}
	emitChangeEvents(context.Background(), nil, Config{Publisher: pub}, tevents.File{}, resultWithNoun(), true)
	emitChangeEvents(context.Background(), nil, Config{ActivityEventBusArn: testBus}, tevents.File{}, resultWithNoun(), true)
	emitChangeEvents(context.Background(), nil, Config{Publisher: pub, ActivityEventBusArn: testBus, SuppressEmission: true}, tevents.File{}, resultWithNoun(), true)
	if pub.calls != 0 {
		t.Fatalf("publisher called %d times while emission was off", pub.calls)
	}

	emitChangeEvents(context.Background(), nil, Config{Publisher: pub, ActivityEventBusArn: testBus}, tevents.File{}, resultWithNoun(), true)
	if pub.calls != 1 {
		t.Fatalf("publisher called %d times with emission on, want 1", pub.calls)
	}
}

func TestEmitChangeEventsSurvivesPublisherErrors(t *testing.T) {
	pub := &countingPublisher{err: errors.New("AccessDeniedException")}
	// emitChangeEvents has no error to return; reaching the assertion is the test.
	emitChangeEvents(context.Background(), nil, Config{Publisher: pub, ActivityEventBusArn: testBus}, tevents.File{}, resultWithNoun(), true)
	if pub.calls == 0 {
		t.Fatalf("publisher was never called")
	}
}

func TestEmitChangeEventsSkipsNearTheDeadline(t *testing.T) {
	pub := &countingPublisher{}
	ctx, cancel := context.WithTimeout(context.Background(), emitDeadlineMargin/2)
	defer cancel()
	emitChangeEvents(ctx, nil, Config{Publisher: pub, ActivityEventBusArn: testBus}, tevents.File{}, resultWithNoun(), true)
	if pub.calls != 0 {
		t.Fatalf("publisher called %d times inside the deadline margin", pub.calls)
	}
}

func TestSuppressForReplay(t *testing.T) {
	cases := map[string]bool{
		`{"Records":[{"s3":{"object":{"key":"k"}}}]}`:                                                false,
		`{"Records":[{"s3":{"object":{"key":"k"}}}],"trailtool":{"replay":true}}`:                    true,
		`{"Records":[{"s3":{"object":{"key":"k"}}}],"trailtool":{"replay":true,"emit_events":true}}`: false,
		`{"source":"aws.s3","detail-type":"Object Created"}`:                                         false,
	}
	for raw, want := range cases {
		if got := suppressForReplay([]byte(raw)); got != want {
			t.Errorf("suppressForReplay(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestActivityEventBusArnFromEnv(t *testing.T) {
	t.Setenv("ACTIVITY_EVENT_BUS_ARN", "")
	if got := ActivityEventBusArnFromEnv(); got != "" {
		t.Fatalf("unset bus = %q, want empty", got)
	}
	t.Setenv("ACTIVITY_EVENT_BUS_ARN", testBus)
	if got := ActivityEventBusArnFromEnv(); got != testBus {
		t.Fatalf("bus = %q, want %q", got, testBus)
	}
}

func TestFileFromKey(t *testing.T) {
	org := fileFromKey("AWSLogs/o-abc123/222222222222/CloudTrail/eu-west-1/2026/10/01/f.json.gz", nil)
	if org.AccountID != "222222222222" || org.Region != "eu-west-1" {
		t.Fatalf("org trail file = %+v", org)
	}
	odd := fileFromKey("custom/f.json.gz", []types.CloudTrailRecord{{RecipientAccountID: "333333333333", AwsRegion: "us-west-2"}})
	if odd.AccountID != "333333333333" || odd.Region != "us-west-2" || odd.Key != "custom/f.json.gz" {
		t.Fatalf("fallback file = %+v", odd)
	}
}
