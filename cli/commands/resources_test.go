package commands

import (
	"testing"
	"time"
)

func TestResourceWindowStartUsesMatchingDateAndTimestampBoundaries(t *testing.T) {
	date, timestamp := resourceWindowStart(
		time.Date(2026, 7, 24, 15, 30, 0, 0, time.UTC),
		7,
	)
	if date != "2026-07-17" || timestamp != "2026-07-17T00:00:00Z" {
		t.Fatalf("window start = %q/%q", date, timestamp)
	}
}
