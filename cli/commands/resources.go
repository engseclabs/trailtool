package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/store"
)

func ResourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resources",
		Short: "AWS resources",
	}
	cmd.AddCommand(resourcesListCmd())
	return cmd
}

func resourcesListCmd() *cobra.Command {
	var days int
	var serviceType string
	var clickops bool
	var minClickOps int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tracked AWS resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			filter := store.ResourceFilter{
				ClickOpsOnly:     clickops,
				ServiceType:      serviceType,
				MinClickOpsCount: minClickOps,
			}
			if days > 0 {
				filter.StartTime = time.Now().AddDate(0, 0, -days).Format("2006-01-02")
			}

			resources, err := s.ListResources(ctx, CustomerID, filter)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				if resources == nil {
					resources = []models.Resource{}
				}
				return printJSON(resources)
			}

			rctx := renderContext()

			if clickops {
				fmt.Print(view.ClickOps(rctx, resources, personLabels(ctx, s)))
				return nil
			}

			fmt.Print(view.Resources(rctx, resources))
			return nil
		},
	}

	cmd.Flags().IntVar(&days, "days", 0, "Filter to last N days")
	cmd.Flags().StringVar(&serviceType, "service", "", "Filter by AWS service type (e.g. s3, lambda, ec2)")
	cmd.Flags().BoolVar(&clickops, "clickops", false, "Only show resources created/modified via web console")
	cmd.Flags().IntVar(&minClickOps, "min-clickops", 1, "Minimum ClickOps events (used with --clickops)")

	return cmd
}
