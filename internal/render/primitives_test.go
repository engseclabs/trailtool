package render

import (
	"strings"
	"testing"
)

func TestKVAlignment(t *testing.T) {
	ctx := colorCtx(false)
	kv := NewKV().
		Add("Role", "Admin").
		Add("Account", "123456789012").
		Add("SID", "abc")
	got := ctx.RenderKV(kv, 0)
	want := strings.Join([]string{
		"Role:     Admin",
		"Account:  123456789012",
		"SID:      abc",
		"",
	}, "\n")
	if got != want {
		t.Errorf("KV mismatch:\n got:\n%q\nwant:\n%q", got, want)
	}
}

func TestKVEmptyValueStillRendered(t *testing.T) {
	ctx := colorCtx(false)
	kv := NewKV().Add("Tags", "")
	got := ctx.RenderKV(kv, 0)
	if !strings.HasPrefix(got, "Tags:") {
		t.Errorf("empty-value pair not rendered: %q", got)
	}
}

func TestHeading(t *testing.T) {
	tests := []struct {
		label string
		count int
		want  string
	}{
		{"Clients", 3, "Clients (3):"},
		{"Session Tags", 0, "Session Tags (0):"},
		{"Session Policy", -1, "Session Policy:"},
	}
	for _, tt := range tests {
		if got := Heading(tt.label, tt.count); got != tt.want {
			t.Errorf("Heading(%q, %d) = %q, want %q", tt.label, tt.count, got, tt.want)
		}
	}
}

func TestSection(t *testing.T) {
	ctx := colorCtx(false)
	got := ctx.Section("Clients (1):", "  body line\n")
	want := "\nClients (1):\n  body line\n"
	if got != want {
		t.Errorf("Section = %q, want %q", got, want)
	}
}

func TestTitle(t *testing.T) {
	ctx := colorCtx(false)
	if got := ctx.Title("me@example.com"); got != "me@example.com\n" {
		t.Errorf("Title = %q", got)
	}
}

func TestStatus(t *testing.T) {
	ctx := colorCtx(false)
	tests := []struct {
		level StatusLevel
		want  string
	}{
		{StatusOK, "[ok] Config: OK"},
		{StatusWarn, "[warn] Config: OK"},
		{StatusFail, "[fail] Config: OK"},
	}
	asciiCtx := Context{Color: false, Unicode: false}
	for _, tt := range tests {
		if got := asciiCtx.Status(tt.level, "Config: OK"); got != tt.want {
			t.Errorf("Status(%d) ascii = %q, want %q", tt.level, got, tt.want)
		}
	}
	// Unicode form leads with the glyph.
	if got := ctx.Status(StatusOK, "Config"); !strings.HasPrefix(got, "✓ ") {
		t.Errorf("unicode Status = %q, want ✓ prefix", got)
	}
}

func TestEmpty(t *testing.T) {
	ctx := colorCtx(false)
	if got := ctx.Empty("No sessions found."); got != "No sessions found." {
		t.Errorf("Empty = %q", got)
	}
}

func TestError(t *testing.T) {
	ctx := colorCtx(false)
	if got := ctx.Error("bad --session value"); got != "Error: bad --session value" {
		t.Errorf("Error = %q", got)
	}
}

func TestErrorHint(t *testing.T) {
	ctx := colorCtx(false)
	got := ctx.ErrorHint("could not reach data store", "Check AWS credentials and region.")
	want := "Error: could not reach data store\nCheck AWS credentials and region."
	if got != want {
		t.Errorf("ErrorHint = %q, want %q", got, want)
	}
	if got := ctx.ErrorHint("msg only", ""); got != "Error: msg only" {
		t.Errorf("ErrorHint no hint = %q", got)
	}
}
