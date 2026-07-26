package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/store"
)

// fakeResetter records whether Reset and CountItems ran and returns canned data.
// Reset replays each result through the progress callback so tests can assert
// the command surfaces progress.
type fakeResetter struct {
	counts        []store.TableReset
	results       []store.TableReset
	resetRan      bool
	countRan      bool
	progressCalls int
	countErr      error
	resetErr      error
}

func (f *fakeResetter) CountItems(context.Context, []string) ([]store.TableReset, error) {
	f.countRan = true
	return f.counts, f.countErr
}

func (f *fakeResetter) Reset(_ context.Context, tables []string, progress store.ResetProgress) ([]store.TableReset, error) {
	f.resetRan = true
	if progress != nil {
		for i, res := range f.results {
			f.progressCalls++
			progress(res.Table, i+1, len(f.results), res.Deleted, true)
		}
	}
	return f.results, f.resetErr
}

// newResetTestCmd wires runReset into a bare command with separate stdout and
// stderr buffers (progress writes to stderr), cobra's own output silenced.
func newResetTestCmd(r resetter, assumeYes bool, stdin string) (cmd *cobra.Command, stdout, stderr *bytes.Buffer) {
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	cmd = &cobra.Command{
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReset(cmd, r, assumeYes)
		},
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetIn(strings.NewReader(stdin))
	return cmd, stdout, stderr
}

func TestResetCancelsWithoutYesConfirmation(t *testing.T) {
	f := &fakeResetter{
		counts: []store.TableReset{{Table: "trailtool-people", Deleted: 3}},
	}
	cmd, out, _ := newResetTestCmd(f, false, "no\n")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("reset error = %v", err)
	}
	if f.resetRan {
		t.Fatal("Reset ran despite the user declining confirmation")
	}
	if !strings.Contains(out.String(), "Reset cancelled") {
		t.Fatalf("output missing cancellation notice: %q", out.String())
	}
}

func TestResetCancelsOnEmptyInput(t *testing.T) {
	f := &fakeResetter{counts: []store.TableReset{{Table: "trailtool-people", Deleted: 1}}}
	cmd, _, _ := newResetTestCmd(f, false, "")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("reset error = %v", err)
	}
	if f.resetRan {
		t.Fatal("Reset ran on empty (EOF) input; must require an explicit yes")
	}
}

func TestResetProceedsOnYes(t *testing.T) {
	oldColor := ColorMode
	ColorMode = "never"
	t.Cleanup(func() { ColorMode = oldColor })

	f := &fakeResetter{
		counts:  []store.TableReset{{Table: "trailtool-people", Deleted: 2}},
		results: []store.TableReset{{Table: "trailtool-people", Deleted: 2}},
	}
	cmd, out, errBuf := newResetTestCmd(f, false, "yes\n")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("reset error = %v", err)
	}
	if !f.resetRan {
		t.Fatal("Reset did not run after the user typed yes")
	}
	if !strings.Contains(out.String(), "Reset complete") {
		t.Fatalf("output missing completion notice: %q", out.String())
	}
	// Progress is written to stderr while clearing.
	if f.progressCalls == 0 {
		t.Fatal("Reset ran without a progress callback")
	}
	if !strings.Contains(errBuf.String(), "clearing 1/1") {
		t.Fatalf("progress not shown on stderr: %q", errBuf.String())
	}
}

func TestResetYesFlagSkipsPrompt(t *testing.T) {
	oldColor := ColorMode
	ColorMode = "never"
	t.Cleanup(func() { ColorMode = oldColor })

	f := &fakeResetter{
		results: []store.TableReset{{Table: "trailtool-sessions", Deleted: 5}},
	}
	// No stdin: --yes must not read from it.
	cmd, out, _ := newResetTestCmd(f, true, "")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("reset error = %v", err)
	}
	if !f.resetRan {
		t.Fatal("--yes did not run Reset")
	}
	if f.countRan {
		t.Fatal("--yes still ran the count query; it should be skipped")
	}
	if strings.Contains(out.String(), "Type 'yes'") {
		t.Fatalf("--yes still prompted: %q", out.String())
	}
}

func TestResetJSONOutput(t *testing.T) {
	oldFormat := Format
	Format = "json"
	t.Cleanup(func() { Format = oldFormat })

	f := &fakeResetter{
		results: []store.TableReset{
			{Table: "trailtool-people", Deleted: 2},
			{Table: "trailtool-relations", Skipped: true},
		},
	}
	cmd, out, errBuf := newResetTestCmd(f, true, "")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("reset error = %v", err)
	}
	var got []store.TableReset
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if len(got) != 2 || got[0].Deleted != 2 || !got[1].Skipped {
		t.Fatalf("unexpected results: %#v", got)
	}
	// JSON mode passes no progress callback, so nothing is written to stderr.
	if f.progressCalls != 0 || errBuf.Len() != 0 {
		t.Fatalf("JSON mode emitted progress: calls=%d stderr=%q", f.progressCalls, errBuf.String())
	}
}
