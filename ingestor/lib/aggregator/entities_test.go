package aggregator

import (
	"reflect"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

func TestProcessServiceEventTracksResources(t *testing.T) {
	services := make(map[string]*types.DynamoDBService)
	event := types.CloudTrailRecord{
		EventSource: "s3.amazonaws.com",
		EventName:   "GetObject",
	}

	processServiceEvent(
		services,
		event,
		"arn:aws:iam::111111111111:role/reader",
		[]string{"s3:bucket:one", "s3:bucket:one", "s3:bucket:two"},
		"2026-07-24",
	)

	got := services[event.EventSource]
	if got == nil {
		t.Fatal("service was not created")
	}
	want := []string{"s3:bucket:one", "s3:bucket:two"}
	if !reflect.DeepEqual(got.ResourcesUsed, want) {
		t.Fatalf("resources = %v, want %v", got.ResourcesUsed, want)
	}
}
