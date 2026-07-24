package render

import (
	"fmt"
	"time"
)

// One timestamp rule, everywhere (§4.5). No view invents its own format.
//
// Absolute form is RFC3339 UTC with a bracketed relative suffix for recency:
//
//	2026-07-22T16:43:18Z [5m ago]
//
// Relative form vocabulary: "just now", "Nm ago", "Nh ago", "yesterday",
// "Nd ago". Intervals render as "start → end" on a Time-styled line.

// relative computes the recency phrase for the gap between now and t.
func relative(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// Relative returns just the recency phrase (e.g. "5m ago") for an RFC3339
// timestamp string, relative to now. An empty string yields "", and an
// unparseable string is returned verbatim.
func Relative(ts string, now time.Time) string {
	if ts == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return relative(t, now)
}

// Timestamp renders an RFC3339 timestamp string in the canonical absolute form
// with a bracketed relative suffix: "2026-07-22T16:43:18Z [5m ago]". The
// absolute portion is normalized to UTC. An empty string yields ""; an
// unparseable string is returned verbatim (no suffix).
func Timestamp(ts string, now time.Time) string {
	if ts == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	abs := t.UTC().Format(time.RFC3339)
	return fmt.Sprintf("%s [%s]", abs, relative(t, now))
}

// Interval renders "start → end" (or the ASCII "start -> end") using the
// canonical absolute UTC form for each endpoint, styled Time by the caller.
// Empty endpoints are omitted; if both are empty the result is "".
func (ctx Context) Interval(startTS, endTS string) string {
	start := absOrRaw(startTS)
	end := absOrRaw(endTS)
	arrow := ctx.Symbol(SymNav)
	switch {
	case start == "" && end == "":
		return ""
	case end == "":
		return start
	case start == "":
		return end
	default:
		return fmt.Sprintf("%s %s %s", start, arrow, end)
	}
}

// absOrRaw normalizes an RFC3339 string to canonical absolute UTC, returning it
// verbatim if unparseable and "" if empty.
func absOrRaw(ts string) string {
	if ts == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.UTC().Format(time.RFC3339)
}
