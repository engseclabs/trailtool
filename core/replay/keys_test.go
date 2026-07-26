package replay

import "testing"

func TestIsReplayable(t *testing.T) {
	cases := map[string]bool{
		"AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json.gz":            true,
		"AWSLogs/1/CloudTrail-Digest/us-east-1/2026/07/25/x.json.gz":     false,
		"AWSLogs/1/CloudTrail-Insight/us-east-1/2026/07/25/x.json.gz":    false,
		"AWSLogs/1/CloudTrail-Aggregated/us-east-1/2026/07/25/x.json.gz": false,
		"AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json":               false,
		"AWSLogs/1/CloudTrail/us-east-1/2026/07/25/":                     false,
		"AWSLogs/o-abc/1/CloudTrail/us-east-1/2026/07/25/org.json.gz":    true,
	}
	for key, want := range cases {
		if got := IsReplayable(key); got != want {
			t.Errorf("IsReplayable(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestDayPrefixesInclusiveAndChronological(t *testing.T) {
	from, _ := ParseDate("2026-07-30")
	to, _ := ParseDate("2026-08-02")
	got, err := DayPrefixes("AWSLogs/123/CloudTrail/us-east-1", from, to)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"AWSLogs/123/CloudTrail/us-east-1/2026/07/30/",
		"AWSLogs/123/CloudTrail/us-east-1/2026/07/31/",
		"AWSLogs/123/CloudTrail/us-east-1/2026/08/01/",
		"AWSLogs/123/CloudTrail/us-east-1/2026/08/02/",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDayPrefixesSingleDay(t *testing.T) {
	d, _ := ParseDate("2026-07-25")
	got, err := DayPrefixes("AWSLogs/1/CloudTrail/eu-west-1/", d, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "AWSLogs/1/CloudTrail/eu-west-1/2026/07/25/" {
		t.Fatalf("got %v", got)
	}
}

func TestDayPrefixesRejectsInvertedRange(t *testing.T) {
	from, _ := ParseDate("2026-07-25")
	to, _ := ParseDate("2026-07-20")
	if _, err := DayPrefixes("base", from, to); err == nil {
		t.Fatal("expected error for --to before --from")
	}
}

func TestParseDate(t *testing.T) {
	if _, err := ParseDate("2026-07-25"); err != nil {
		t.Errorf("date form rejected: %v", err)
	}
	if got, err := ParseDate("2026-07-25T13:00:00Z"); err != nil || got.Hour() != 13 {
		t.Errorf("RFC3339 form: got %v err %v", got, err)
	}
	if _, err := ParseDate("July 25"); err == nil {
		t.Error("expected error for freeform date")
	}
}

func TestCloudTrailBaseRequiresAccountAndRegion(t *testing.T) {
	if _, err := CloudTrailBase("", "us-east-1"); err == nil {
		t.Error("expected error when account missing")
	}
	base, err := CloudTrailBase("123", "us-east-1")
	if err != nil || base != "AWSLogs/123/CloudTrail/us-east-1/" {
		t.Fatalf("base = %q err %v", base, err)
	}
}
