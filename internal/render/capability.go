// Package render is TrailTool's deterministic, AWS-free terminal rendering
// layer. It imports only the standard library and golang.org/x/term — never the
// AWS SDK and never core/models — so every primitive is fully unit-testable by
// constructing a Context directly.
//
// A single Context captures the terminal's capabilities (color, Unicode, width)
// in one detection pass at command start. It is then threaded to every view;
// nothing re-reads the environment mid-render. See docs/design/cli-output.md §4.
package render

import (
	"io"
	"os"

	"golang.org/x/term"
)

// ColorMode is the resolved value of the global --color flag.
type ColorMode int

const (
	// ColorAuto enables color iff stdout is a TTY, TERM != dumb, and NO_COLOR
	// is unset. This is the default.
	ColorAuto ColorMode = iota
	// ColorAlways forces color on regardless of TTY (for `less -R` etc.).
	ColorAlways
	// ColorNever forces color off.
	ColorNever
)

// ParseColorMode maps a --color flag value to a ColorMode. Unknown values fall
// back to auto; callers that want strict validation should check first.
func ParseColorMode(s string) (ColorMode, bool) {
	switch s {
	case "auto", "":
		return ColorAuto, true
	case "always":
		return ColorAlways, true
	case "never":
		return ColorNever, true
	default:
		return ColorAuto, false
	}
}

// Context carries the terminal capabilities resolved once per command. Views
// name semantic style roles and symbol concepts against it; they never inspect
// the environment themselves. --format json bypasses Context entirely: JSON
// output never consults it.
type Context struct {
	Color   bool      // ANSI styling on?
	Unicode bool      // Unicode symbols vs ASCII fallback?
	Width   int       // terminal columns; DefaultWidth when unknown
	Out     io.Writer // stdout
	Err     io.Writer // stderr
}

// DefaultWidth is the assumed terminal width when the real width is unknown
// (non-TTY, or GetSize error). Redirected output is stable and diff-friendly.
const DefaultWidth = 80

// env abstracts the process environment for deterministic testing.
type env struct {
	lookupEnv func(string) (string, bool)
	isTTY     func(fd uintptr) bool
	getSize   func(fd uintptr) (width int, ok bool)
	stdoutFd  uintptr
}

func osEnv() env {
	return env{
		lookupEnv: os.LookupEnv,
		isTTY:     func(fd uintptr) bool { return term.IsTerminal(int(fd)) },
		getSize: func(fd uintptr) (int, bool) {
			w, _, err := term.GetSize(int(fd))
			if err != nil || w <= 0 {
				return 0, false
			}
			return w, true
		},
		stdoutFd: os.Stdout.Fd(),
	}
}

// Detect resolves a Context from the real process environment for the given
// color mode, writing human output to out and diagnostics to err. It is called
// once at command start; the returned Context is then threaded to every view.
func Detect(mode ColorMode, out, err io.Writer) Context {
	return detect(mode, out, err, osEnv())
}

// detect is the testable core of Detect. See docs/design/cli-output.md §4.1 for
// the resolution rules encoded here.
func detect(mode ColorMode, out, errw io.Writer, e env) Context {
	_, noColor := e.lookupEnv("NO_COLOR")
	termVal, _ := e.lookupEnv("TERM")
	dumb := termVal == "dumb"
	isTTY := e.isTTY(e.stdoutFd)

	// Color resolution (§4.1): --color=never / NO_COLOR win; then --color=always;
	// then auto = TTY && TERM!=dumb && NO_COLOR unset.
	var color bool
	switch mode {
	case ColorNever:
		color = false
	case ColorAlways:
		color = true
	default: // ColorAuto
		color = isTTY && !dumb && !noColor
	}
	if noColor {
		color = false
	}

	// Unicode is on unless TERM=dumb — a conservative proxy for "can't render
	// box-drawing/symbols". --color=never does NOT force ASCII: a mono terminal
	// can still show ✓.
	unicode := !dumb

	// Width from x/term; on error or non-TTY, DefaultWidth.
	width := DefaultWidth
	if isTTY {
		if w, ok := e.getSize(e.stdoutFd); ok {
			width = w
		}
	}

	return Context{
		Color:   color,
		Unicode: unicode,
		Width:   width,
		Out:     out,
		Err:     errw,
	}
}
