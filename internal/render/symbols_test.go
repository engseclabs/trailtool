package render

import "testing"

func TestSymbolUnicodeAndASCII(t *testing.T) {
	tests := []struct {
		sym            Symbol
		unicode, ascii string
	}{
		{SymSuccess, "✓", "[ok]"},
		{SymWarning, "⚠", "[warn]"},
		{SymFailure, "✗", "[fail]"},
		{SymDenied, "⊘", "(denied)"},
		{SymLineage, "↳", "->"},
		{SymNav, "→", "->"},
		{SymParent, "↑", "^"},
		{SymSource, "←", "<-"},
		{SymEllipsis, "…", "..."},
	}
	uni := Context{Unicode: true}
	asc := Context{Unicode: false}
	for _, tt := range tests {
		if got := uni.Symbol(tt.sym); got != tt.unicode {
			t.Errorf("unicode Symbol(%d) = %q, want %q", tt.sym, got, tt.unicode)
		}
		if got := asc.Symbol(tt.sym); got != tt.ascii {
			t.Errorf("ascii Symbol(%d) = %q, want %q", tt.sym, got, tt.ascii)
		}
	}
}
