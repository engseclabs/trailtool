package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/replay"
)

func TestBuildReplayOptionsSelection(t *testing.T) {
	t.Run("prefix mode", func(t *testing.T) {
		opts, err := buildReplayOptions(&replayFlags{bucket: "b", prefix: "AWSLogs/1/CloudTrail/us-east-1/2026/07/"})
		if err != nil {
			t.Fatal(err)
		}
		if len(opts.Prefixes) != 1 || opts.Prefixes[0] != "AWSLogs/1/CloudTrail/us-east-1/2026/07/" {
			t.Fatalf("prefixes = %v", opts.Prefixes)
		}
	})

	t.Run("day range expands to per-day prefixes", func(t *testing.T) {
		opts, err := buildReplayOptions(&replayFlags{
			bucket: "b", account: "123", region: "us-east-1",
			from: "2026-07-25", to: "2026-07-26",
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(opts.Prefixes) != 2 {
			t.Fatalf("prefixes = %v, want 2 days", opts.Prefixes)
		}
	})

	t.Run("prefix and range together is an error", func(t *testing.T) {
		if _, err := buildReplayOptions(&replayFlags{bucket: "b", prefix: "p/", from: "2026-07-25", to: "2026-07-26"}); err == nil {
			t.Fatal("expected error for --prefix with --from/--to")
		}
	})

	t.Run("range without both bounds is an error", func(t *testing.T) {
		if _, err := buildReplayOptions(&replayFlags{bucket: "b", from: "2026-07-25"}); err == nil {
			t.Fatal("expected error for --from without --to")
		}
	})

	t.Run("sub-day instant is rejected", func(t *testing.T) {
		_, err := buildReplayOptions(&replayFlags{
			bucket: "b", account: "1", region: "us-east-1",
			from: "2026-07-25T10:00:00Z", to: "2026-07-26",
		})
		if err == nil {
			t.Fatal("expected date-only rejection of an RFC3339 instant")
		}
	})
}

type stubLister struct{ keys []string }

func (s stubLister) ListKeys(context.Context, string) ([]string, error) { return s.keys, nil }

type stubInvoker struct{ failKeys map[string]bool }

func (s stubInvoker) Invoke(_ context.Context, _, key string) error {
	if s.failKeys[key] {
		return errors.New("boom")
	}
	return nil
}

// newReplayTestCmd wires runReplay into a bare command. stdout (the JSON/text
// result) and stderr (errors, progress) are separate buffers, and cobra's own
// usage/error printing is silenced, mirroring the real root command.
func newReplayTestCmd(deps replayDeps, opts replay.Options) (cmd *cobra.Command, stdout, stderr *bytes.Buffer) {
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	cmd = &cobra.Command{
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplay(cmd, deps, opts)
		},
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	return cmd, stdout, stderr
}

// Finding #6: JSON mode must not report success when objects failed.
func TestReplayJSONFailureExitsNonZero(t *testing.T) {
	oldFormat := Format
	Format = "json"
	t.Cleanup(func() { Format = oldFormat })

	deps := replayDeps{
		lister:  stubLister{keys: []string{"p/a.json.gz", "p/b.json.gz"}},
		invoker: stubInvoker{failKeys: map[string]bool{"p/b.json.gz": true}},
	}
	cmd, stdout, _ := newReplayTestCmd(deps, replay.Options{Bucket: "bkt", Prefixes: []string{"p/"}})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("JSON mode returned nil error despite a failed object")
	}
	// The result must still be encoded to stdout (callers parse it) before the error.
	var res replay.Result
	if jerr := json.Unmarshal(stdout.Bytes(), &res); jerr != nil {
		t.Fatalf("JSON not emitted: %q (%v)", stdout.String(), jerr)
	}
	if len(res.Failed) != 1 || res.Failed[0] != "p/b.json.gz" {
		t.Fatalf("failed = %v", res.Failed)
	}
}

func TestReplaySuccessExitsZero(t *testing.T) {
	oldFormat, oldColor := Format, ColorMode
	Format, ColorMode = "text", "never"
	t.Cleanup(func() { Format, ColorMode = oldFormat, oldColor })

	deps := replayDeps{
		lister:  stubLister{keys: []string{"p/a.json.gz"}},
		invoker: stubInvoker{},
	}
	cmd, stdout, _ := newReplayTestCmd(deps, replay.Options{Bucket: "bkt", Prefixes: []string{"p/"}})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("replay error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Replayed 1/1") {
		t.Fatalf("output = %q", stdout.String())
	}
}
