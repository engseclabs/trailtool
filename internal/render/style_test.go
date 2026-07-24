package render

import (
	"io"
	"strings"
	"testing"
)

func colorCtx(color bool) Context {
	return Context{Color: color, Unicode: true, Width: 80, Out: io.Discard, Err: io.Discard}
}

func TestStyleOff(t *testing.T) {
	ctx := colorCtx(false)
	for r := Title; r <= Nav; r++ {
		got := ctx.Style(r, "value")
		if got != "value" {
			t.Errorf("Style(%d) with color off = %q, want unchanged", r, got)
		}
	}
}

func TestStyleOnWraps(t *testing.T) {
	ctx := colorCtx(true)
	got := ctx.Style(Ident, "me@example.com")
	if !strings.HasPrefix(got, ansiCyan) || !strings.HasSuffix(got, ansiReset) {
		t.Errorf("Ident style = %q, want cyan-wrapped", got)
	}
}

func TestStyleEmptyNeverWrapped(t *testing.T) {
	ctx := colorCtx(true)
	if got := ctx.Style(Fail, ""); got != "" {
		t.Errorf("Style of empty string = %q, want empty", got)
	}
}

func TestStyleRolesWithoutCodes(t *testing.T) {
	// Count and Time map to no ANSI prefix — they pass through even with color on.
	ctx := colorCtx(true)
	if got := ctx.Style(Count, "42"); got != "42" {
		t.Errorf("Count style = %q, want unchanged", got)
	}
	if got := ctx.Style(Time, "2026-07-22T16:43:18Z"); got != "2026-07-22T16:43:18Z" {
		t.Errorf("Time style = %q, want unchanged", got)
	}
}

func TestStripANSI(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{ansiCyan + "id" + ansiReset, "id"},
		{ansiBold + ansiDim + "hdr" + ansiReset, "hdr"},
		{"a" + ansiRed + "b" + ansiReset + "c", "abc"},
	}
	for _, tt := range tests {
		if got := StripANSI(tt.in); got != tt.want {
			t.Errorf("StripANSI(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestNoColorParity is the §9 additivity proof: stripping ANSI from a colored
// render must equal the Color:false render, for every role.
func TestNoColorParity(t *testing.T) {
	on := colorCtx(true)
	off := colorCtx(false)
	for r := Title; r <= Nav; r++ {
		colored := on.Style(r, "sample text")
		plain := off.Style(r, "sample text")
		if StripANSI(colored) != plain {
			t.Errorf("role %d: stripped colored %q != plain %q", r, StripANSI(colored), plain)
		}
	}
}
