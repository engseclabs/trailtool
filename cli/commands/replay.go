package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/replay"
	"github.com/engseclabs/trailtool/internal/render"
)

// replayDeps are the AWS-backed collaborators the replay driver needs. A package
// var builds them from ambient config; tests swap in fakes.
type replayDeps struct {
	lister  replay.Lister
	invoker replay.Invoker
}

var openReplayDeps = func(ctx context.Context, bucket, function string) (replayDeps, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return replayDeps{}, err
	}
	return replayDeps{
		lister:  replay.S3Lister{Client: s3.NewFromConfig(cfg), Bucket: bucket},
		invoker: replay.LambdaInvoker{Client: lambda.NewFromConfig(cfg), Function: function},
	}, nil
}

type replayFlags struct {
	bucket      string
	function    string
	prefix      string
	from        string
	to          string
	account     string
	region      string
	concurrency int
	dryRun      bool
	cursorPath  string
	noResume    bool
}

// ReplayCmd re-ingests historical CloudTrail objects from S3 through the
// existing ingestor Lambda (docs/design/cloudtrail-replay.md).
func ReplayCmd() *cobra.Command {
	var f replayFlags
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Re-ingest historical CloudTrail logs from S3 to rebuild TrailTool data",
		Long: "Lists CloudTrail log objects in a time range (--from/--to with --account\n" +
			"and --region) or under an explicit --prefix, then invokes the ingestor\n" +
			"Lambda once per object. Uses the normal ingestion path, so replayed and\n" +
			"live data are identical. Interrupted runs resume from a local cursor.\n\n" +
			"Reset first (trailtool reset) for a clean rebuild, or replay onto existing\n" +
			"data to backfill; the ingestor skips objects it has already processed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := buildReplayOptions(&f)
			if err != nil {
				return fatal("%v", err)
			}
			deps, err := openReplayDeps(cmd.Context(), f.bucket, f.function)
			if err != nil {
				return fatalAWS("Set AWS_PROFILE and AWS_REGION, then re-authenticate.", err)
			}
			cur := replayCursor(&f)
			return runReplay(cmd, deps, cur, opts, &f)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&f.bucket, "bucket", "", "S3 bucket holding the CloudTrail logs (required)")
	flags.StringVar(&f.function, "function", "trailtool-ingestor", "Ingestor Lambda function name")
	flags.StringVar(&f.prefix, "prefix", "", "Replay every object under this S3 key prefix")
	flags.StringVar(&f.from, "from", "", "Start of range (YYYY-MM-DD or RFC3339); needs --account and --region")
	flags.StringVar(&f.to, "to", "", "End of range, inclusive (YYYY-MM-DD or RFC3339)")
	flags.StringVar(&f.account, "account", "", "Account ID for the standard CloudTrail key layout")
	flags.StringVar(&f.region, "region", "", "Region for the standard CloudTrail key layout")
	flags.IntVar(&f.concurrency, "concurrency", 4, "Max in-flight Lambda invocations")
	flags.BoolVar(&f.dryRun, "dry-run", false, "List and count matching objects without invoking the ingestor")
	flags.StringVar(&f.cursorPath, "cursor", "", "Resume-cursor file path (default: derived from the target)")
	flags.BoolVar(&f.noResume, "no-resume", false, "Ignore any resume cursor and replay the whole range")
	_ = cmd.MarkFlagRequired("bucket")
	return cmd
}

// buildReplayOptions validates the selection flags and resolves them to the S3
// prefixes to list. Exactly one of --prefix or --from/--to must be given.
func buildReplayOptions(f *replayFlags) (replay.Options, error) {
	opts := replay.Options{Bucket: f.bucket, Concurrency: f.concurrency, DryRun: f.dryRun}

	switch {
	case f.prefix != "" && (f.from != "" || f.to != ""):
		return opts, fmt.Errorf("use either --prefix or --from/--to, not both")
	case f.prefix != "":
		opts.Prefixes = []string{f.prefix}
	case f.from != "" && f.to != "":
		base, err := replay.CloudTrailBase(f.account, f.region)
		if err != nil {
			return opts, err
		}
		from, err := replay.ParseDate(f.from)
		if err != nil {
			return opts, err
		}
		to, err := replay.ParseDate(f.to)
		if err != nil {
			return opts, err
		}
		prefixes, err := replay.DayPrefixes(base, from, to)
		if err != nil {
			return opts, err
		}
		opts.Prefixes = prefixes
	default:
		return opts, fmt.Errorf("specify --prefix, or --from and --to together")
	}
	return opts, nil
}

// replayCursor returns the resume cursor: disabled by --no-resume or --dry-run,
// otherwise a local file keyed to the target so distinct ranges don't collide.
func replayCursor(f *replayFlags) replay.Cursor {
	if f.noResume || f.dryRun {
		return replay.NopCursor{}
	}
	path := f.cursorPath
	if path == "" {
		path = defaultCursorPath(f)
	}
	return replay.FileCursor{Path: path}
}

func defaultCursorPath(f *replayFlags) string {
	target := f.prefix
	if target == "" {
		target = f.account + "_" + f.region + "_" + f.from + "_" + f.to
	}
	name := "trailtool-replay-" + sanitizeForFilename(f.bucket+"_"+target) + ".cursor"
	return filepath.Join(cursorDir(), name)
}

// runReplay executes the driver and renders the outcome.
func runReplay(cmd *cobra.Command, deps replayDeps, cur replay.Cursor, opts replay.Options, f *replayFlags) error {
	out := cmd.OutOrStdout()
	rctx := renderContext()
	rctx.Out = out
	rctx.Err = cmd.ErrOrStderr()

	var progress replay.Progress
	if Format != "json" && !opts.DryRun {
		progress = func(done, total int, key string) {
			fmt.Fprintf(rctx.Err, "\r%s", rctx.Style(render.Muted,
				fmt.Sprintf("replaying %d/%d  %s", done, total, filepath.Base(key))))
		}
	}

	res, err := replay.Run(cmd.Context(), deps.lister, deps.invoker, cur, opts, progress)
	if progress != nil {
		fmt.Fprintln(rctx.Err)
	}
	if err != nil {
		return fatalAWS("Re-run to resume from the last completed object.", err)
	}

	if Format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	printReplayResult(rctx, opts, res)
	if len(res.Failed) > 0 {
		return fmt.Errorf("%d objects failed to replay", len(res.Failed))
	}
	return nil
}

// cursorDir returns the directory for resume-cursor files: the user cache dir
// when available, else the working directory.
func cursorDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return dir
	}
	return "."
}

// sanitizeForFilename replaces path-hostile characters so a bucket/prefix maps
// to a stable, filesystem-safe cursor filename.
func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func printReplayResult(rctx render.Context, opts replay.Options, res replay.Result) {
	if opts.DryRun {
		fmt.Fprintln(rctx.Out, rctx.Status(render.StatusOK,
			fmt.Sprintf("Dry run: %d objects match (skipped %d already done). None invoked.", res.Matched, res.Skipped)))
		return
	}
	level := render.StatusOK
	if len(res.Failed) > 0 {
		level = render.StatusWarn
	}
	fmt.Fprintln(rctx.Out, rctx.Status(level,
		fmt.Sprintf("Replayed %d/%d objects (skipped %d already done, %d failed).",
			res.Processed, res.Matched, res.Skipped, len(res.Failed))))
	for _, key := range res.Failed {
		fmt.Fprintf(rctx.Out, "  %s %s\n", rctx.Symbol(render.SymNav), rctx.Style(render.Muted, "failed: "+key))
	}
}
