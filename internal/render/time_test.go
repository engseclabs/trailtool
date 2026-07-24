package render

import (
	"testing"
	"time"
)

var refNow = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

func TestRelative(t *testing.T) {
	tests := []struct {
		name string
		ts   string
		want string
	}{
		{"just now", "2026-07-24T11:59:30Z", "just now"},
		{"minutes", "2026-07-24T11:55:00Z", "5m ago"},
		{"hours", "2026-07-24T09:00:00Z", "3h ago"},
		{"yesterday", "2026-07-23T10:00:00Z", "yesterday"},
		{"days", "2026-07-20T12:00:00Z", "4d ago"},
		{"empty", "", ""},
		{"unparseable verbatim", "not-a-time", "not-a-time"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Relative(tt.ts, refNow); got != tt.want {
				t.Errorf("Relative(%q) = %q, want %q", tt.ts, got, tt.want)
			}
		})
	}
}

func TestTimestamp(t *testing.T) {
	tests := []struct {
		name string
		ts   string
		want string
	}{
		{"utc with suffix", "2026-07-24T11:55:00Z", "2026-07-24T11:55:00Z [5m ago]"},
		{"normalizes offset to utc", "2026-07-24T07:55:00-04:00", "2026-07-24T11:55:00Z [5m ago]"},
		{"empty", "", ""},
		{"unparseable verbatim", "garbage", "garbage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Timestamp(tt.ts, refNow); got != tt.want {
				t.Errorf("Timestamp(%q) = %q, want %q", tt.ts, got, tt.want)
			}
		})
	}
}

func TestInterval(t *testing.T) {
	uni := Context{Unicode: true}
	asc := Context{Unicode: false}
	start, end := "2026-07-24T10:00:00Z", "2026-07-24T11:00:00Z"

	if got := uni.Interval(start, end); got != "2026-07-24T10:00:00Z → 2026-07-24T11:00:00Z" {
		t.Errorf("unicode interval = %q", got)
	}
	if got := asc.Interval(start, end); got != "2026-07-24T10:00:00Z -> 2026-07-24T11:00:00Z" {
		t.Errorf("ascii interval = %q", got)
	}
	if got := uni.Interval(start, ""); got != "2026-07-24T10:00:00Z" {
		t.Errorf("missing end = %q, want start only", got)
	}
	if got := uni.Interval("", end); got != "2026-07-24T11:00:00Z" {
		t.Errorf("missing start = %q, want end only", got)
	}
	if got := uni.Interval("", ""); got != "" {
		t.Errorf("both empty = %q, want empty", got)
	}
}
