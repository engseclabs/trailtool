package render

import (
	"io"
	"testing"
)

// fakeEnv builds an env for detect() from an explicit table, so capability
// resolution is tested deterministically without touching the real terminal.
func fakeEnv(vars map[string]string, tty bool, width int) env {
	return env{
		lookupEnv: func(k string) (string, bool) { v, ok := vars[k]; return v, ok },
		isTTY:     func(uintptr) bool { return tty },
		getSize: func(uintptr) (int, bool) {
			if width <= 0 {
				return 0, false
			}
			return width, true
		},
		stdoutFd: 1,
	}
}

func TestDetectColor(t *testing.T) {
	tests := []struct {
		name      string
		mode      ColorMode
		vars      map[string]string
		tty       bool
		wantColor bool
	}{
		{"auto tty", ColorAuto, nil, true, true},
		{"auto non-tty", ColorAuto, nil, false, false},
		{"auto dumb term", ColorAuto, map[string]string{"TERM": "dumb"}, true, false},
		{"auto no_color", ColorAuto, map[string]string{"NO_COLOR": ""}, true, false},
		{"auto no_color with value", ColorAuto, map[string]string{"NO_COLOR": "1"}, true, false},
		{"always non-tty", ColorAlways, nil, false, true},
		{"always dumb", ColorAlways, map[string]string{"TERM": "dumb"}, true, true},
		{"always no_color loses", ColorAlways, map[string]string{"NO_COLOR": "1"}, true, false},
		{"never tty", ColorNever, nil, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := detect(tt.mode, io.Discard, io.Discard, fakeEnv(tt.vars, tt.tty, 120))
			if ctx.Color != tt.wantColor {
				t.Errorf("Color = %v, want %v", ctx.Color, tt.wantColor)
			}
		})
	}
}

func TestDetectUnicode(t *testing.T) {
	// Unicode on unless TERM=dumb; --color=never must NOT force ASCII.
	tests := []struct {
		name string
		mode ColorMode
		vars map[string]string
		want bool
	}{
		{"default", ColorAuto, nil, true},
		{"dumb off", ColorAuto, map[string]string{"TERM": "dumb"}, false},
		{"never keeps unicode", ColorNever, nil, true},
		{"no_color keeps unicode", ColorAuto, map[string]string{"NO_COLOR": "1"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := detect(tt.mode, io.Discard, io.Discard, fakeEnv(tt.vars, true, 120))
			if ctx.Unicode != tt.want {
				t.Errorf("Unicode = %v, want %v", ctx.Unicode, tt.want)
			}
		})
	}
}

func TestDetectWidth(t *testing.T) {
	tests := []struct {
		name  string
		tty   bool
		width int
		want  int
	}{
		{"tty reports width", true, 132, 132},
		{"non-tty falls back", false, 132, DefaultWidth},
		{"tty getsize error falls back", true, 0, DefaultWidth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := detect(ColorAuto, io.Discard, io.Discard, fakeEnv(nil, tt.tty, tt.width))
			if ctx.Width != tt.want {
				t.Errorf("Width = %d, want %d", ctx.Width, tt.want)
			}
		})
	}
}

func TestParseColorMode(t *testing.T) {
	tests := []struct {
		in    string
		want  ColorMode
		valid bool
	}{
		{"auto", ColorAuto, true},
		{"", ColorAuto, true},
		{"always", ColorAlways, true},
		{"never", ColorNever, true},
		{"bogus", ColorAuto, false},
	}
	for _, tt := range tests {
		got, ok := ParseColorMode(tt.in)
		if got != tt.want || ok != tt.valid {
			t.Errorf("ParseColorMode(%q) = (%v, %v), want (%v, %v)", tt.in, got, ok, tt.want, tt.valid)
		}
	}
}
