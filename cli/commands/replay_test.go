package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/replay"
)

func TestValidateReplaySelection(t *testing.T) {
	t.Run("prefix alone is ok", func(t *testing.T) {
		if err := validateReplaySelection(&replayFlags{prefix: "p/"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("from and to together is ok", func(t *testing.T) {
		if err := validateReplaySelection(&replayFlags{from: "2026-07-25", to: "2026-07-26"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("prefix and range together is an error", func(t *testing.T) {
		if err := validateReplaySelection(&replayFlags{prefix: "p/", from: "2026-07-25", to: "2026-07-26"}); err == nil {
			t.Fatal("expected error for --prefix with --from/--to")
		}
	})
	t.Run("range without both bounds is an error", func(t *testing.T) {
		if err := validateReplaySelection(&replayFlags{from: "2026-07-25"}); err == nil {
			t.Fatal("expected error for --from without --to")
		}
	})
	t.Run("nothing selected is an error", func(t *testing.T) {
		if err := validateReplaySelection(&replayFlags{}); err == nil {
			t.Fatal("expected error when no selection given")
		}
	})
}

func TestBuildReplayOptions(t *testing.T) {
	t.Run("prefix mode carries the resolved bucket", func(t *testing.T) {
		opts, err := buildReplayOptions(&replayFlags{prefix: "AWSLogs/1/CloudTrail/us-east-1/2026/07/"}, "resolved-bucket")
		if err != nil {
			t.Fatal(err)
		}
		if opts.Bucket != "resolved-bucket" {
			t.Fatalf("bucket = %q, want the resolved value", opts.Bucket)
		}
		if len(opts.Prefixes) != 1 || opts.Prefixes[0] != "AWSLogs/1/CloudTrail/us-east-1/2026/07/" {
			t.Fatalf("prefixes = %v", opts.Prefixes)
		}
	})

	t.Run("day range expands to per-day prefixes", func(t *testing.T) {
		opts, err := buildReplayOptions(&replayFlags{
			account: "123", region: "us-east-1",
			from: "2026-07-25", to: "2026-07-26",
		}, "b")
		if err != nil {
			t.Fatal(err)
		}
		if len(opts.Prefixes) != 2 {
			t.Fatalf("prefixes = %v, want 2 days", opts.Prefixes)
		}
	})

	t.Run("sub-day instant is rejected", func(t *testing.T) {
		_, err := buildReplayOptions(&replayFlags{
			account: "1", region: "us-east-1",
			from: "2026-07-25T10:00:00Z", to: "2026-07-26",
		}, "b")
		if err == nil {
			t.Fatal("expected date-only rejection of an RFC3339 instant")
		}
	})
}

func TestBucketFromStackPrefersOutputThenParameter(t *testing.T) {
	out := cfntypes.Stack{
		Outputs: []cfntypes.Output{
			{OutputKey: aws.String("CloudTrailBucketName"), OutputValue: aws.String("from-output")},
		},
		Parameters: []cfntypes.Parameter{
			{ParameterKey: aws.String("CloudTrailBucketName"), ParameterValue: aws.String("from-param")},
		},
	}
	if got := bucketFromStack(out); got != "from-output" {
		t.Fatalf("bucket = %q, want output to win", got)
	}

	paramOnly := cfntypes.Stack{
		Parameters: []cfntypes.Parameter{
			{ParameterKey: aws.String("CloudTrailBucketName"), ParameterValue: aws.String("from-param")},
		},
	}
	if got := bucketFromStack(paramOnly); got != "from-param" {
		t.Fatalf("bucket = %q, want parameter fallback", got)
	}

	if got := bucketFromStack(cfntypes.Stack{}); got != "" {
		t.Fatalf("bucket = %q, want empty for a stack without the key", got)
	}
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
