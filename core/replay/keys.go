// Package replay drives ingestion of historical CloudTrail objects already in
// S3: it lists the objects in a chosen range and invokes the ingestor Lambda
// once per object with a synthetic S3 event, reusing the live ingestion path.
// See docs/design/cloudtrail-replay.md.
package replay

import (
	"fmt"
	"strings"
	"time"
)

// IsReplayable reports whether an S3 key is a CloudTrail event log the ingestor
// should process. It mirrors the Lambda's own skips (ingest.go): only
// gzipped event logs, never Digest/Insight/Aggregated sidecar files. This keeps
// replay from invoking the Lambda on objects it would just skip.
func IsReplayable(key string) bool {
	if !strings.HasSuffix(key, ".json.gz") {
		return false
	}
	if strings.Contains(key, "/CloudTrail-Digest/") ||
		strings.Contains(key, "/CloudTrail-Insight/") ||
		strings.Contains(key, "/CloudTrail-Aggregated/") {
		return false
	}
	return true
}

// DayPrefixes returns the CloudTrail S3 key prefixes covering [from, to]
// inclusive by day, in ascending (chronological) order. CloudTrail writes under
// AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/, so one prefix per day in
// the range narrows the listing to exactly the days that can contain matching
// objects. base is everything up to and including ".../CloudTrail/<region>/".
//
// Boundary days are listed whole; per-event eventTime, not the file, decides
// where activity lands, so over-listing a few hours at the edges is harmless
// (docs/design/cloudtrail-replay.md §5).
func DayPrefixes(base string, from, to time.Time) ([]string, error) {
	if to.Before(from) {
		return nil, fmt.Errorf("--to %s is before --from %s", to.Format(dateLayout), from.Format(dateLayout))
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	var prefixes []string
	day := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
	last := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	for !day.After(last) {
		prefixes = append(prefixes, base+day.Format("2006/01/02")+"/")
		day = day.AddDate(0, 0, 1)
	}
	return prefixes, nil
}

const dateLayout = "2006-01-02"

// ParseDate accepts a calendar date (YYYY-MM-DD) in UTC. v1 is day-granular on
// purpose: the S3 layout is day-partitioned, so a sub-day instant would still
// have to replay whole-day objects, and letting those out-of-range events into
// the projection would be wrong, not harmless (docs/design/cloudtrail-replay.md
// §5). Sub-day precision is a deferred follow-up.
func ParseDate(s string) (time.Time, error) {
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid date %q (want YYYY-MM-DD)", s)
	}
	return t.UTC(), nil
}

// CloudTrailBase builds the standard-layout prefix up to the region segment:
// AWSLogs/<account>/CloudTrail/<region>/. Operators with a non-standard layout
// (org trails, custom bucket prefix) pass an explicit --prefix instead.
func CloudTrailBase(account, region string) (string, error) {
	if account == "" || region == "" {
		return "", fmt.Errorf("time-range replay needs --account and --region (or use --prefix)")
	}
	return fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/", account, region), nil
}
