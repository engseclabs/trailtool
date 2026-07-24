package render

import "unicode/utf8"

// Middle-truncation for long identifiers — ARNs, emails, role names, resource
// ids — preserving the distinguishing head and tail (§6):
//
//	aws-reserved/…/AdministratorAccess_7d88aa2a
//
// The marker is the ellipsis symbol (… or ...), so callers get the right width
// for the current terminal.

// Truncate shortens s to at most max display columns, middle-truncating with the
// context's ellipsis marker when it doesn't fit. Widths are counted in runes
// (TrailTool identifiers are ASCII in practice; this keeps multibyte-safe). A
// max at or below the marker width falls back to a plain head cut.
func (ctx Context) Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	n := utf8.RuneCountInString(s)
	if n <= max {
		return s
	}
	marker := ctx.Symbol(SymEllipsis)
	mw := utf8.RuneCountInString(marker)
	if max <= mw {
		return headRunes(marker, max)
	}
	keep := max - mw
	head := (keep + 1) / 2 // bias extra rune to the head
	tail := keep - head
	return headRunes(s, head) + marker + tailRunes(s, tail)
}

// headRunes returns the first n runes of s.
func headRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i, count := 0, 0
	for i < len(s) {
		if count == n {
			break
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		count++
	}
	return s[:i]
}

// tailRunes returns the last n runes of s.
func tailRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	total := utf8.RuneCountInString(s)
	if n >= total {
		return s
	}
	skip := total - n
	i, count := 0, 0
	for i < len(s) && count < skip {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		count++
	}
	return s[i:]
}
