package aggregator

import "testing"

func TestSummarizeCountsOrdersByCount(t *testing.T) {
	got := summarizeCounts(map[string]int{"ThrottlingException": 2, "AccessDenied": 5, "NoSuchKey": 2})
	if got != "AccessDenied=5 NoSuchKey=2 ThrottlingException=2" {
		t.Fatalf("summary = %q", got)
	}
}
