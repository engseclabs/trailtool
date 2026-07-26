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
	cmd.AddCommand(resourcesDetailCmd())
	return cmd
}

func resourcesListCmd() *cobra.Command {
	var serviceType string
	var accountID string
	var clickops bool
	var minClickOps int
	var limit int
	var nounFilter nounListFilter

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tracked AWS resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			normalized, err := nounFilter.normalize(time.Now())
			if err != nil {
				return fatal("%v", err)
			}
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			filter := store.ResourceFilter{
				ClickOpsOnly:     clickops,
				ServiceType:      serviceType,
				MinClickOpsCount: minClickOps,
				StartTime:        normalized.after,
				EndTime:          normalized.before,
			}

			resources, err := s.ListResources(ctx, CustomerID, filter)
			if err != nil {
				return fatal("%v", err)
			}
			resources = filterNouns(resources, normalized,
				func(resource models.Resource) string { return resource.LastSeen },
				func(resource models.Resource) int { return resource.TotalDeniedEvents })
			if accountID != "" {
				filtered := resources[:0]
				for _, resource := range resources {
					if resource.AccountID == accountID {
						filtered = append(filtered, resource)
					}
				}
				resources = filtered
			}
			resources = capList(resources, limit)

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

	addNounListFilterFlags(cmd, &nounFilter)
	cmd.Flags().StringVar(&serviceType, "service", "", "Filter by AWS service type (e.g. s3, lambda, ec2)")
	cmd.Flags().StringVar(&accountID, "account", "", "Only show resources in this AWS account")
	cmd.Flags().BoolVar(&clickops, "clickops", false, "Only show resources created/modified via web console")
	cmd.Flags().IntVar(&minClickOps, "min-clickops", 1, "Minimum ClickOps events (used with --clickops)")
	addListLimitFlag(cmd, &limit)

	return cmd
}

func resourcesDetailCmd() *cobra.Command {
	var limit int
	var all bool
	var includeDeniedDetails bool

	cmd := &cobra.Command{
		Use:   "detail <rid>",
		Short: "Show resource details",
		Long: `Show a resource and its related activity using the RID from
'trailtool resources list'. An unambiguous RID prefix is accepted.

Example:
  trailtool resources detail fyf7wf`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			relationLimit, err := detailRelationLimit(cmd, limit, all)
			if err != nil {
				return fatal("%v", err)
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			matches, err := s.FindResourcesByRIDPrefix(ctx, CustomerID, args[0])
			if err != nil {
				return fatal("%v", err)
			}
			resource, err := resolveResourceMatches(args[0], matches)
			if err != nil {
				return fatal("%v", err)
			}

			related, err := s.LoadRelatedNouns(
				ctx,
				CustomerID,
				store.RelationKindResource,
				resource.ResourceKey,
				relationLimit,
			)
			if err != nil {
				return fatal("%v", err)
			}
			resource.ApplyRelationshipCounts(related.Counts)
			detail := models.ResourceDetail{Resource: *resource, Related: related}

			if Format == "json" {
				return printJSON(detail)
			}

			fmt.Print(view.ResourceDetail(renderContext(), &detail, includeDeniedDetails))
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", defaultDetailLimit, "Maximum rows in each related section")
	cmd.Flags().BoolVar(&all, "all", false, "Show every related record")
	cmd.Flags().BoolVar(&includeDeniedDetails, "include-denied-details", false, "Show denied event breakdowns")
	return cmd
}
