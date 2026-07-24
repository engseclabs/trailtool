package render

import (
	"strings"
	"testing"
)

func TestTableAlignment(t *testing.T) {
	ctx := colorCtx(false)
	tbl := NewTable(
		Column{Header: "#", Align: AlignRight},
		Column{Header: "PERSON", Align: AlignLeft},
		Column{Header: "EVENTS", Align: AlignRight},
	)
	tbl.Row("1", "me@example.com", "42")
	tbl.Row("2", "you@x.io", "7")

	got := ctx.RenderTable(tbl, 0)
	want := strings.Join([]string{
		"#  PERSON          EVENTS",
		"1  me@example.com      42",
		"2  you@x.io             7",
		"",
	}, "\n")
	if got != want {
		t.Errorf("table mismatch:\n got:\n%q\nwant:\n%q", got, want)
	}
}

func TestTableZeroRendersPresent(t *testing.T) {
	// §4.4: zero renders as "0", never blank.
	ctx := colorCtx(false)
	tbl := NewTable(Column{Header: "DENIED", Align: AlignRight})
	tbl.Row("0")
	got := ctx.RenderTable(tbl, 0)
	if !strings.Contains(got, "0") {
		t.Errorf("zero count missing from %q", got)
	}
}

func TestTableIndent(t *testing.T) {
	ctx := colorCtx(false)
	tbl := NewTable(Column{Header: "SVC", Align: AlignLeft})
	tbl.Row("s3")
	got := ctx.RenderTable(tbl, 2)
	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("line %q not indented two spaces", line)
		}
	}
}

func TestTableAlignmentWithColor(t *testing.T) {
	// Column widths must be measured on visible text, so ANSI-styled cells still
	// align. Strip the colored render and compare to the plain render.
	on := colorCtx(true)
	off := colorCtx(false)
	build := func(ctx Context) string {
		tbl := NewTable(
			Column{Header: "ID", Align: AlignLeft},
			Column{Header: "N", Align: AlignRight},
		)
		tbl.Row(ctx.Style(Ident, "sid-abc"), ctx.Style(Count, "3"))
		tbl.Row(ctx.Style(Ident, "x"), ctx.Style(Count, "100"))
		return ctx.RenderTable(tbl, 0)
	}
	if got := StripANSI(build(on)); got != build(off) {
		t.Errorf("colored table (stripped) != plain table:\n%q\nvs\n%q", got, build(off))
	}
}

func TestTableNoTrailingWhitespace(t *testing.T) {
	ctx := colorCtx(false)
	tbl := NewTable(
		Column{Header: "A", Align: AlignLeft},
		Column{Header: "LONGCOL", Align: AlignLeft},
	)
	tbl.Row("x", "y")
	for _, line := range strings.Split(strings.TrimRight(ctx.RenderTable(tbl, 0), "\n"), "\n") {
		if strings.TrimRight(line, " ") != line {
			t.Errorf("line has trailing whitespace: %q", line)
		}
	}
}
