package render

// Symbol is a semantic concept that renders as a Unicode glyph when the terminal
// can display it and as an ASCII fallback otherwise. Session-relationship
// meaning is always carried by words first; the symbol is a leading accent,
// never the sole carrier. See docs/design/cli-output.md §4.3.
type Symbol int

const (
	// SymSuccess: ✓ / [ok]
	SymSuccess Symbol = iota
	// SymWarning: ⚠ / [warn]
	SymWarning
	// SymFailure: ✗ / [fail]
	SymFailure
	// SymDenied: ⊘ / (denied)
	SymDenied
	// SymLineage marks child-of / nav-down: ↳ / ->
	SymLineage
	// SymNav marks a copy-paste command line: → / ->
	SymNav
	// SymParent marks assumed-from / parent (up): ↑ / ^
	SymParent
	// SymSource marks login / agent source (in): ← / <-
	SymSource
	// SymEllipsis is the middle-truncation marker: … / ...
	SymEllipsis
)

type symbolPair struct {
	unicode string
	ascii   string
}

var symbolTable = map[Symbol]symbolPair{
	SymSuccess:  {"✓", "[ok]"},
	SymWarning:  {"⚠", "[warn]"},
	SymFailure:  {"✗", "[fail]"},
	SymDenied:   {"⊘", "(denied)"},
	SymLineage:  {"↳", "->"},
	SymNav:      {"→", "->"},
	SymParent:   {"↑", "^"},
	SymSource:   {"←", "<-"},
	SymEllipsis: {"…", "..."},
}

// Symbol returns the glyph for concept s: the Unicode form when ctx.Unicode is
// on, the ASCII fallback otherwise.
func (ctx Context) Symbol(s Symbol) string {
	p, ok := symbolTable[s]
	if !ok {
		return ""
	}
	if ctx.Unicode {
		return p.unicode
	}
	return p.ascii
}
