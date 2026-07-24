package render

import (
	"strings"
	"unicode/utf8"
)

// Align controls a column's horizontal alignment.
type Align int

const (
	// AlignLeft left-justifies (default; text columns).
	AlignLeft Align = iota
	// AlignRight right-justifies (numeric columns, §4.4).
	AlignRight
)

// Column declares one table column: its UPPERCASE header text (§4.4) and its
// alignment. Header casing is the caller's responsibility — the table styles but
// does not re-case, so views control the exact header string.
type Column struct {
	Header string
	Align  Align
}

// Table is a deterministic column layout. It computes per-column widths from
// content, styles the header row with the Header role, and pads/aligns cells.
// It performs no color or truncation on cell bodies — cells arrive already
// styled and already width-fitted by the view (which owns column tiers and
// middle-truncation, §6). The table only lays out and aligns.
//
// Because cells may already contain ANSI escapes, width is measured on the
// visible (ANSI-stripped) content so alignment stays correct with color on.
type Table struct {
	cols []Column
	rows [][]string
}

// NewTable starts a table with the given columns.
func NewTable(cols ...Column) *Table {
	return &Table{cols: cols}
}

// Row appends a row. Extra cells beyond the column count are ignored; missing
// trailing cells render empty.
func (t *Table) Row(cells ...string) *Table {
	t.rows = append(t.rows, cells)
	return t
}

// cell returns the i-th cell of a row, or "" if absent.
func cell(row []string, i int) string {
	if i < len(row) {
		return row[i]
	}
	return ""
}

// visibleWidth is the display width of s ignoring ANSI escapes, counted in
// runes.
func visibleWidth(s string) int {
	return utf8.RuneCountInString(StripANSI(s))
}

// pad aligns s to width w columns, measuring visible width so ANSI-styled cells
// still align. Content already wider than w is returned unchanged.
func pad(s string, w int, a Align) string {
	gap := w - visibleWidth(s)
	if gap <= 0 {
		return s
	}
	fill := strings.Repeat(" ", gap)
	if a == AlignRight {
		return fill + s
	}
	return s + fill
}

// Render lays the table out into a string with a styled header row followed by
// the data rows. Columns are separated by two spaces; trailing whitespace on
// each line is trimmed so redirected output stays diff-clean. Each line
// (including the header) is prefixed with indent spaces. A table with no rows
// renders header-only — callers that want an "empty" message use Empty instead.
func (ctx Context) RenderTable(t *Table, indent int) string {
	// Column widths: max of header and every cell's visible width.
	widths := make([]int, len(t.cols))
	for i, c := range t.cols {
		widths[i] = utf8.RuneCountInString(c.Header)
	}
	for _, row := range t.rows {
		for i := range t.cols {
			if w := visibleWidth(cell(row, i)); w > widths[i] {
				widths[i] = w
			}
		}
	}

	pre := strings.Repeat(" ", indent)
	var b strings.Builder

	// Header row.
	headerCells := make([]string, len(t.cols))
	for i, c := range t.cols {
		headerCells[i] = pad(c.Header, widths[i], c.Align)
	}
	b.WriteString(pre)
	b.WriteString(ctx.Style(Header, strings.TrimRight(strings.Join(headerCells, "  "), " ")))
	b.WriteByte('\n')

	// Data rows.
	for _, row := range t.rows {
		cells := make([]string, len(t.cols))
		for i := range t.cols {
			cells[i] = pad(cell(row, i), widths[i], t.cols[i].Align)
		}
		b.WriteString(pre)
		b.WriteString(strings.TrimRight(strings.Join(cells, "  "), " "))
		b.WriteByte('\n')
	}

	return b.String()
}
