package render

import "fmt"

// Error rendering (§5). Two shapes, both one line and Fail-styled, both destined
// for stderr:
//
//   - Validation errors: "Error: <msg>".
//   - AWS/service errors: a human "Error: <msg>" plus a one-line hint; the raw
//     SDK error is surfaced only under debug, which the command layer handles.
//
// These return strings; the command layer writes them to ctx.Err and sets the
// exit code. Keeping them as pure string builders keeps them unit-testable.

// Error renders a one-line "Error: <msg>" (§5, validation errors), Fail-styled.
// No trailing newline.
func (ctx Context) Error(msg string) string {
	return ctx.Style(Fail, "Error: "+msg)
}

// ErrorHint renders an AWS/service error as two lines: the human "Error: <msg>"
// (Fail-styled) and a Muted one-line hint beneath it. When hint is empty only
// the error line is returned. No trailing newline.
func (ctx Context) ErrorHint(msg, hint string) string {
	line := ctx.Error(msg)
	if hint == "" {
		return line
	}
	return fmt.Sprintf("%s\n%s", line, ctx.Style(Muted, hint))
}
