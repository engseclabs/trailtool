package render

import "strings"

// KV renders "key facts" — the aligned Label: value block under a view's title
// (§5). Labels are Title Case (the caller supplies the exact text; KV does not
// re-case) and are colon-terminated and left-aligned to a common width so values
// line up. Labels carry no role by default; values arrive already styled by the
// view.
type KV struct {
	pairs [][2]string
}

// NewKV starts an empty key-value block.
func NewKV() *KV { return &KV{} }

// Add appends a label/value pair. A pair with an empty value is still rendered
// (the label with nothing after the colon) so absent-but-expected facts stay
// visible; callers omit truly irrelevant facts by not adding them.
func (k *KV) Add(label, value string) *KV {
	k.pairs = append(k.pairs, [2]string{label, value})
	return k
}

// Render lays the pairs out as "Label:  value" lines, indented by indent spaces,
// with labels padded to a common width so values align. Label width is measured
// on visible text. Trailing whitespace is trimmed.
func (ctx Context) RenderKV(k *KV, indent int) string {
	width := 0
	for _, p := range k.pairs {
		if w := visibleWidth(p[0]); w > width {
			width = w
		}
	}
	pre := strings.Repeat(" ", indent)
	var b strings.Builder
	for _, p := range k.pairs {
		label := pad(p[0]+":", width+1, AlignLeft)
		line := pre + label + "  " + p[1]
		b.WriteString(strings.TrimRight(line, " "))
		b.WriteByte('\n')
	}
	return b.String()
}
