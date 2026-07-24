package render

import (
	"fmt"
	"strings"
)

// Section renders the standard section separator (§4.4): a blank line, then a
// Title-Case heading, with the body indented two spaces. There are no ASCII
// rules or "--- … ---" separators — the blank line plus heading is the
// separator.
//
// A section heading commonly carries a count, e.g. "Clients (3):". Views build
// that string; Section only styles and spaces it.

// BodyIndent is the standard two-space indent for section bodies (§4.4).
const BodyIndent = 2

// Section writes a section: a leading blank line, the Header-styled heading, and
// the already-rendered body (which the caller indents, typically via the indent
// argument to RenderTable/RenderKV). The body is written verbatim; Section does
// not re-indent it.
func (ctx Context) Section(heading, body string) string {
	var b strings.Builder
	b.WriteByte('\n')
	b.WriteString(ctx.Style(Header, heading))
	b.WriteByte('\n')
	b.WriteString(body)
	return b.String()
}

// Title renders the top-of-view identity line (§4.2, §5): the Title-styled text
// followed by a newline. No leading blank line — the title opens the view.
func (ctx Context) Title(s string) string {
	return ctx.Style(Title, s) + "\n"
}

// Heading formats a section heading with an optional count suffix, e.g.
// Heading("Clients", 3) -> "Clients (3):" and Heading("Session Tags", -1) ->
// "Session Tags:". A negative count omits the parenthetical. The result is
// unstyled text intended to be passed to Section.
func Heading(label string, count int) string {
	if count < 0 {
		return label + ":"
	}
	return fmt.Sprintf("%s (%d):", label, count)
}
