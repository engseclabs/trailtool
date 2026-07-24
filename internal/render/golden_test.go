package render

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update regenerates the golden files: go test ./internal/render -update
var update = flag.Bool("update", false, "update golden files")

// goldenComposite renders a small composite of every primitive so the golden
// files capture the primitives working together at a given width and color mode.
// This is the AWS-free stand-in for the cli/view golden tests (§9) until the view
// layer lands in a later PR; the primitives here are exactly what those views
// will call.
func goldenComposite(ctx Context) string {
	out := ""
	out += ctx.Title("me@example.com")

	kv := NewKV().
		Add("Role", ctx.Style(Ident, "AdministratorAccess")).
		Add("Account", "123456789012").
		Add("SID", ctx.Style(Ident, "sig-abc123")).
		Add("Events", ctx.Style(Count, "42"))
	out += ctx.RenderKV(kv, 0)

	tbl := NewTable(
		Column{Header: "EVENT", Align: AlignLeft},
		Column{Header: "COUNT", Align: AlignRight},
		Column{Header: "DENIED", Align: AlignRight},
	)
	longID := ctx.Truncate("aws-reserved/sso.amazonaws.com/us-east-1/AdministratorAccess_7d88aa2a", ctx.Width/3)
	tbl.Row("s3:GetObject", ctx.Style(Count, "30"), ctx.Style(Denied, "0"))
	tbl.Row(longID, ctx.Style(Count, "12"), ctx.Style(Denied, ctx.Symbol(SymDenied)+" 3"))
	out += ctx.Section(Heading("Top Events", 2), ctx.RenderTable(tbl, BodyIndent))

	out += "\n"
	out += ctx.Status(StatusOK, "Config: OK") + "\n"
	out += ctx.Status(StatusFail, "Data access: FAIL") + "\n"
	out += ctx.Empty("No resources found.") + "\n"
	out += ctx.Error("bad --session value") + "\n"

	return out
}

func TestGoldenComposite(t *testing.T) {
	cases := []struct {
		name  string
		width int
		color bool
		uni   bool
	}{
		{"w60_plain", 60, false, true},
		{"w80_plain", 80, false, true},
		{"w100_plain", 100, false, true},
		{"w132_plain", 132, false, true},
		{"w100_color", 100, true, true},
		{"w80_ascii", 80, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := Context{Color: c.color, Unicode: c.uni, Width: c.width}
			got := goldenComposite(ctx)
			path := filepath.Join("testdata", "composite_"+c.name+".golden")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run -update to create): %v", err)
			}
			if got != string(want) {
				t.Errorf("golden mismatch for %s:\n got:\n%s\nwant:\n%s", c.name, got, want)
			}
		})
	}
}

// TestGoldenNoColorParity proves, at composite scale, that stripping ANSI from a
// colored render yields the plain render (§9 additivity), independent of the
// per-role unit check.
func TestGoldenNoColorParity(t *testing.T) {
	colored := Context{Color: true, Unicode: true, Width: 100}
	plain := Context{Color: false, Unicode: true, Width: 100}
	if StripANSI(goldenComposite(colored)) != goldenComposite(plain) {
		t.Error("stripped colored composite != plain composite")
	}
}
