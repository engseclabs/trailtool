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

// fakeResetter records whether Reset ran and returns canned counts.
type fakeResetter struct {
	counts   []store.TableReset
	results  []store.TableReset
	resetRan bool
	countErr error
	resetErr error
}

func (f *fakeResetter) CountItems(context.Context, []string) ([]store.TableReset, error) {
	return f.counts, f.countErr
}

func (f *fakeResetter) Reset(context.Context, []string) ([]store.TableReset, error) {
	f.resetRan = true
	return f.results, f.resetErr
}

func newResetTestCmd(r resetter, assumeYes bool, stdin string) (*cobra.Command, *bytes.Buffer) {
	var out bytes.Buffer
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReset(cmd, r, assumeYes)
		},
	}
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	return cmd, &out
}

func TestResetCancelsWithoutYesConfirmation(t *testing.T) {
	f := &fakeResetter{
		counts: []store.TableReset{{Table: "trailtool-people", Deleted: 3}},
	}
	cmd, out := newResetTestCmd(f, false, "no\n")
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
	cmd, _ := newResetTestCmd(f, false, "")
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
	cmd, out := newResetTestCmd(f, false, "yes\n")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("reset error = %v", err)
	}
	if !f.resetRan {
		t.Fatal("Reset did not run after the user typed yes")
	}
	if !strings.Contains(out.String(), "Reset complete") {
		t.Fatalf("output missing completion notice: %q", out.String())
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
	cmd, out := newResetTestCmd(f, true, "")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("reset error = %v", err)
	}
	if !f.resetRan {
		t.Fatal("--yes did not run Reset")
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
	cmd, out := newResetTestCmd(f, true, "")
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
}
