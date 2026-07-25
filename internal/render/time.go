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
// "Nd ago". Intervals append one relative suffix for the range endpoint.

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
// timestamp or YYYY-MM-DD date, relative to now. An empty string yields "",
// and an unparseable string is returned verbatim.
func Relative(ts string, now time.Time) string {
	if ts == "" {
		return ""
	}
	t, dateOnly, ok := parseTime(ts)
	if !ok {
		return ts
	}
	if dateOnly {
		return relativeDate(t, now)
	}
	return relative(t, now)
}

// Timestamp renders an RFC3339 timestamp or YYYY-MM-DD date in canonical
// absolute form with a bracketed relative suffix. RFC3339 values normalize to
// UTC. An empty string yields ""; an unparseable string is returned verbatim.
func Timestamp(ts string, now time.Time) string {
	if ts == "" {
		return ""
	}
	t, dateOnly, ok := parseTime(ts)
	if !ok {
		return ts
	}
	if dateOnly {
		return fmt.Sprintf("%s [%s]", t.Format(time.DateOnly), relativeDate(t, now))
	}
	abs := t.UTC().Format(time.RFC3339)
	return fmt.Sprintf("%s [%s]", abs, relative(t, now))
}

// Timestamp renders an RFC3339 timestamp against the Context's clock.
func (ctx Context) Timestamp(ts string) string {
	return Timestamp(ts, ctx.now())
}

// Relative renders an RFC3339 timestamp as a compact relative value.
func (ctx Context) Relative(ts string) string {
	return Relative(ts, ctx.now())
}

// Interval renders "start → end [relative]" (or the ASCII arrow) using the
// canonical absolute UTC form for each endpoint. The relative suffix describes
// the end of the interval, or the start when the end is unavailable.
func (ctx Context) Interval(startTS, endTS string) string {
	start := absOrRaw(startTS)
	end := absOrRaw(endTS)
	arrow := ctx.Symbol(SymNav)
	reference := endTS
	if reference == "" {
		reference = startTS
	}
	suffix := ""
	if relativeValue := Relative(reference, ctx.now()); relativeValue != "" && relativeValue != reference {
		suffix = " [" + relativeValue + "]"
	}
	switch {
	case start == "" && end == "":
		return ""
	case end == "":
		return start + suffix
	case start == "":
		return end + suffix
	default:
		return fmt.Sprintf("%s %s %s%s", start, arrow, end, suffix)
	}
}

func (ctx Context) now() time.Time {
	if ctx.Now.IsZero() {
		return time.Now().UTC()
	}
	return ctx.Now
}

// absOrRaw normalizes an RFC3339 string to canonical absolute UTC, returning it
// verbatim if unparseable and "" if empty.
func absOrRaw(ts string) string {
	if ts == "" {
		return ""
	}
	t, dateOnly, ok := parseTime(ts)
	if !ok {
		return ts
	}
	if dateOnly {
		return t.Format(time.DateOnly)
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(ts string) (time.Time, bool, bool) {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, false, true
	}
	if t, err := time.Parse(time.DateOnly, ts); err == nil {
		return t, true, true
	}
	return time.Time{}, false, false
}

func relativeDate(t, now time.Time) string {
	date := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	nowUTC := now.UTC()
	today := time.Date(nowUTC.Year(), nowUTC.Month(), nowUTC.Day(), 0, 0, 0, 0, time.UTC)
	days := int(today.Sub(date).Hours() / 24)
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "yesterday"
	default:
		return fmt.Sprintf("%dd ago", days)
	}
}
