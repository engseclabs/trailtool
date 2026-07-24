package render

import "fmt"

// StatusLevel is the health of a single status check.
type StatusLevel int

const (
	// StatusOK renders ✓ / [ok], Success-styled.
	StatusOK StatusLevel = iota
	// StatusWarn renders ⚠ / [warn], Warn-styled.
	StatusWarn
	// StatusFail renders ✗ / [fail], Fail-styled.
	StatusFail
)

// statusParts maps a level to its symbol concept and style role.
func statusParts(l StatusLevel) (Symbol, Role) {
	switch l {
	case StatusOK:
		return SymSuccess, Success
	case StatusWarn:
		return SymWarning, Warn
	default:
		return SymFailure, Fail
	}
}

// Status renders a single status line for the `status` command (§5): a leading
// symbol accent followed by the label, e.g. "✓ Config: OK". Color is never the
// only signal — the symbol carries the state in mono/ASCII terminals. The
// returned string has no trailing newline.
func (ctx Context) Status(level StatusLevel, label string) string {
	sym, role := statusParts(level)
	return fmt.Sprintf("%s %s", ctx.Style(role, ctx.Symbol(sym)), ctx.Style(role, label))
}

// Empty renders the standard empty-result line (§5), e.g.
// Empty("No sessions found.") -> the Muted-styled message. Every list command
// prints exactly one of these to stdout instead of header-only output. No
// trailing newline.
func (ctx Context) Empty(message string) string {
	return ctx.Style(Muted, message)
}
