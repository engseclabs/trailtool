package render

import "strings"

// Role is a semantic style name. Views name a role, never a raw color, so
// removing color changes nothing but the escape bytes. See
// docs/design/cli-output.md §4.2.
type Role int

const (
	// Title is the top-of-view identity line (bold).
	Title Role = iota
	// Header styles table column headers and section headings (bold + dim).
	Header
	// Muted is secondary/derived detail and hints (dim).
	Muted
	// Success is healthy status (green).
	Success
	// Warn is warnings and the ClickOps flag (yellow).
	Warn
	// Fail is failures (red).
	Fail
	// Denied is denied-event counts (red).
	Denied
	// Count is numeric aggregates (default; bold on emphasis).
	Count
	// Ident is emails, role names, SIDs, resource ids (cyan).
	Ident
	// Time is timestamps (default).
	Time
	// Nav is the copy-paste "→ trailtool …" navigation lines (dim).
	Nav
)

// ANSI select-graphic-rendition codes. Only bold, dim, and 3-bit color are used
// — no 256-color, truecolor, italics, or underline (§4.4).
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

// roleCodes returns the ANSI prefix(es) for a role. Empty means "no styling".
func roleCodes(r Role) string {
	switch r {
	case Title:
		return ansiBold
	case Header:
		return ansiBold + ansiDim
	case Muted, Nav:
		return ansiDim
	case Success:
		return ansiGreen
	case Warn:
		return ansiYellow
	case Fail, Denied:
		return ansiRed
	case Ident:
		return ansiCyan
	case Count, Time:
		return ""
	default:
		return ""
	}
}

// Style wraps s in the ANSI sequence for role r when ctx.Color is on, and
// returns s unchanged (identity, no bytes) when off. Empty input is never
// wrapped, so styling a zero-length string stays zero-length.
func (ctx Context) Style(r Role, s string) string {
	if !ctx.Color || s == "" {
		return s
	}
	codes := roleCodes(r)
	if codes == "" {
		return s
	}
	return codes + s + ansiReset
}

// ansiEscapePrefix is the CSI introducer (ESC [) that begins every SGR escape
// sequence StripANSI removes.
const ansiEscapePrefix = "\x1b["

// StripANSI removes CSI SGR escape sequences from s. It exists so tests can
// prove color is purely additive: stripping a colored render must equal the
// Color:false render.
func StripANSI(s string) string {
	if !strings.Contains(s, ansiEscapePrefix) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// Skip until the final byte of the CSI sequence (a letter, here 'm').
			j := i + 2
			for j < len(s) && !(s[j] >= '@' && s[j] <= '~') {
				j++
			}
			if j < len(s) {
				j++ // consume the final byte
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
