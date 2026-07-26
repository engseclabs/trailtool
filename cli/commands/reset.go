package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/store"
	"github.com/engseclabs/trailtool/internal/render"
)

// resetter empties the derived tables and reports per-table counts. The store
// satisfies it; tests inject a fake so the command is exercised without AWS.
type resetter interface {
	CountItems(ctx context.Context, tables []string) ([]store.TableReset, error)
	Reset(ctx context.Context, tables []string, progress store.ResetProgress) ([]store.TableReset, error)
}

// openResetter builds a store-backed resetter from the ambient AWS config. It is
// a package var so tests replace it with a fake.
var openResetter = func(ctx context.Context) (resetter, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return store.NewStoreFromConfig(cfg), nil
}

// ResetCmd empties TrailTool's derived tables so the projection can be rebuilt
// from the CloudTrail log via replay (docs/design/cloudtrail-replay.md §4).
func ResetCmd() *cobra.Command {
	var assumeYes bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Delete all derived TrailTool data so it can be rebuilt from CloudTrail",
		Long: "Empties every derived DynamoDB table (people, sessions, roles, resources,\n" +
			"accounts, services, relations, identity-links) and the ingested-files\n" +
			"markers. The CloudTrail log is never touched, so a reset is recoverable by\n" +
			"replaying it. This is destructive and irreversible except by replay.\n\n" +
			"Run reset while live delivery is quiet. It clears all tables and does not\n" +
			"do so atomically, so an object the ingestor writes mid-reset could land\n" +
			"inconsistently. Reset, then replay the range to rebuild.",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := openResetter(cmd.Context())
			if err != nil {
				return fatalAWS("Set AWS_PROFILE and AWS_REGION, then re-authenticate.", err)
			}
			return runReset(cmd, r, assumeYes)
		},
	}
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "Skip the confirmation prompt")
	return cmd
}

// runReset prints what will be cleared, asks for confirmation unless --yes is
// set, then truncates the tables and reports per-table deletion counts.
func runReset(cmd *cobra.Command, r resetter, assumeYes bool) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	tables := store.DerivedTables()

	// The count query only feeds the confirmation prompt, so --yes skips it.
	if !assumeYes {
		counts, err := r.CountItems(ctx, tables)
		if err != nil {
			return fatalAWS("Check that the ingestor stack is deployed and reachable.", err)
		}
		confirmed, err := confirmReset(out, cmd.InOrStdin(), counts)
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(out, "Reset cancelled.")
			return nil
		}
	}

	rctx := renderContext()
	rctx.Err = cmd.ErrOrStderr()
	var progress store.ResetProgress
	if Format != "json" {
		progress = func(table string, idx, total, deleted int, done bool) {
			fmt.Fprintf(rctx.Err, "\r%s", rctx.Style(render.Muted,
				fmt.Sprintf("clearing %d/%d  %-28s %d deleted", idx, total, table, deleted)))
		}
	}

	results, err := r.Reset(ctx, tables, progress)
	if progress != nil {
		fmt.Fprintln(rctx.Err)
	}
	if err != nil {
		return fatalAWS("The reset may be partial; re-run to finish clearing.", err)
	}

	if Format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	printResetResults(cmd, results)
	return nil
}

// confirmReset shows the tables and their approximate item counts, then requires
// the user to type "yes". Any other input (or EOF) cancels.
func confirmReset(out io.Writer, in io.Reader, counts []store.TableReset) (bool, error) {
	total := 0
	fmt.Fprintln(out, "This will delete all derived TrailTool data:")
	for _, c := range counts {
		if c.Skipped {
			fmt.Fprintf(out, "  %-28s (not deployed, skipped)\n", c.Table)
			continue
		}
		total += c.Deleted
		fmt.Fprintf(out, "  %-28s ~%d items\n", c.Table, c.Deleted)
	}
	fmt.Fprintf(out, "\nThe CloudTrail log is not touched; rebuild with 'trailtool replay'.\n")
	fmt.Fprintf(out, "Type 'yes' to delete ~%d items: ", total)

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, nil // EOF with no input cancels
	}
	return strings.TrimSpace(line) == "yes", nil
}

func printResetResults(cmd *cobra.Command, results []store.TableReset) {
	rctx := renderContext()
	rctx.Out = cmd.OutOrStdout()
	rctx.Err = cmd.ErrOrStderr()

	deleted := 0
	for _, res := range results {
		if res.Skipped {
			continue
		}
		deleted += res.Deleted
		fmt.Fprintf(rctx.Out, "  %s  %s\n",
			rctx.Style(render.Ident, res.Table),
			rctx.Style(render.Count, fmt.Sprintf("%d deleted", res.Deleted)))
	}
	fmt.Fprintln(rctx.Out, rctx.Status(render.StatusOK,
		fmt.Sprintf("Reset complete: %d items deleted. Rebuild with 'trailtool replay'.", deleted)))
}
