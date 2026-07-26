package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

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
	bucket   string
	function string
	prefix   string
	from     string
	to       string
	account  string
	region   string
	dryRun   bool
}

// ReplayCmd re-ingests historical CloudTrail objects from S3 through the
// existing ingestor Lambda (docs/design/cloudtrail-replay.md).
func ReplayCmd() *cobra.Command {
	var f replayFlags
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Re-ingest historical CloudTrail logs from S3 to rebuild TrailTool data",
		Long: "Lists CloudTrail log objects for a day range (--from/--to with --account\n" +
			"and --region) or under an explicit --prefix, then invokes the ingestor\n" +
			"Lambda once per object, in chronological order. Uses the normal ingestion\n" +
			"path, so replayed and live data are identical.\n\n" +
			"Replay past (closed) days. Their objects are separate from what live\n" +
			"delivery writes to today's prefix, so replay and live ingestion can run at\n" +
			"the same time. Replaying the current, still-growing day is not supported.\n" +
			"Reset first (trailtool reset) for a clean rebuild from scratch.",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := buildReplayOptions(&f)
			if err != nil {
				return fatal("%v", err)
			}
			deps, err := openReplayDeps(cmd.Context(), f.bucket, f.function)
			if err != nil {
				return fatalAWS("Set AWS_PROFILE and AWS_REGION, then re-authenticate.", err)
			}
			return runReplay(cmd, deps, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&f.bucket, "bucket", "", "S3 bucket holding the CloudTrail logs (required)")
	flags.StringVar(&f.function, "function", "trailtool-ingestor", "Ingestor Lambda function name")
	flags.StringVar(&f.prefix, "prefix", "", "Replay every object under this S3 key prefix (single account/region)")
	flags.StringVar(&f.from, "from", "", "First day of range, YYYY-MM-DD (needs --account and --region)")
	flags.StringVar(&f.to, "to", "", "Last day of range, inclusive, YYYY-MM-DD")
	flags.StringVar(&f.account, "account", "", "Account ID for the standard CloudTrail key layout")
	flags.StringVar(&f.region, "region", "", "Region for the standard CloudTrail key layout")
	flags.BoolVar(&f.dryRun, "dry-run", false, "List and count matching objects without invoking the ingestor")
	_ = cmd.MarkFlagRequired("bucket")
	return cmd
}

// buildReplayOptions validates the selection flags and resolves them to the S3
// prefixes to list. Exactly one of --prefix or --from/--to must be given.
func buildReplayOptions(f *replayFlags) (replay.Options, error) {
	opts := replay.Options{Bucket: f.bucket, DryRun: f.dryRun}

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

// runReplay executes the driver and renders the outcome. It returns a non-nil
// error whenever any object failed, so both text and JSON callers see a failure
// and the process exits non-zero.
func runReplay(cmd *cobra.Command, deps replayDeps, opts replay.Options) error {
	out := cmd.OutOrStdout()
	rctx := renderContext()
	rctx.Out = out
	rctx.Err = cmd.ErrOrStderr()

	var progress replay.Progress
	if Format != "json" && !opts.DryRun {
		progress = func(done, total int, key string) {
			fmt.Fprintf(rctx.Err, "\r%s", rctx.Style(render.Muted,
				fmt.Sprintf("replaying %d/%d  %s", done, total, path.Base(key))))
		}
	}

	res, err := replay.Run(cmd.Context(), deps.lister, deps.invoker, opts, progress)
	if progress != nil {
		fmt.Fprintln(rctx.Err)
	}
	if err != nil {
		return fatalAWS("Re-run the range; the ingestor skips objects already done.", err)
	}

	if Format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(res); encErr != nil {
			return encErr
		}
	} else {
		printReplayResult(rctx, opts, res)
	}
	if len(res.Failed) > 0 {
		return fmt.Errorf("%d objects failed to replay", len(res.Failed))
	}
	return nil
}

func printReplayResult(rctx render.Context, opts replay.Options, res replay.Result) {
	if opts.DryRun {
		fmt.Fprintln(rctx.Out, rctx.Status(render.StatusOK,
			fmt.Sprintf("Dry run: %d objects match. None invoked.", res.Matched)))
		return
	}
	level := render.StatusOK
	if len(res.Failed) > 0 {
		level = render.StatusWarn
	}
	fmt.Fprintln(rctx.Out, rctx.Status(level,
		fmt.Sprintf("Replayed %d/%d objects (%d failed).",
			res.Processed, res.Matched, len(res.Failed))))
	for _, key := range res.Failed {
		fmt.Fprintf(rctx.Out, "  %s %s\n", rctx.Symbol(render.SymNav), rctx.Style(render.Muted, "failed: "+key))
	}
}
