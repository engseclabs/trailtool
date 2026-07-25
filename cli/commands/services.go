package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/store"
)

func ServicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "services",
		Short: "AWS services",
	}
	cmd.AddCommand(servicesListCmd())
	cmd.AddCommand(servicesDetailCmd())
	return cmd
}

func servicesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked AWS services",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			services, err := s.ListServices(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(services)
			}

			fmt.Print(view.Services(renderContext(), services))
			return nil
		},
	}
}

func servicesDetailCmd() *cobra.Command {
	var limit int
	var all bool

	cmd := &cobra.Command{
		Use:   "detail <event-source>",
		Short: "Show service details",
		Args:  cobra.ExactArgs(1),
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

			eventSource := args[0]
			svc, err := s.GetService(ctx, CustomerID, eventSource)
			if err != nil {
				return fatal("%v", err)
			}
			if svc == nil && !strings.Contains(eventSource, ".") {
				eventSource += ".amazonaws.com"
				svc, err = s.GetService(ctx, CustomerID, eventSource)
				if err != nil {
					return fatal("%v", err)
				}
			}
			if svc == nil {
				return fatal("service not found: %s", args[0])
			}

			related, err := s.LoadRelatedNouns(
				ctx,
				CustomerID,
				store.RelationKindService,
				svc.EventSource,
				relationLimit,
			)
			if err != nil {
				return fatal("%v", err)
			}
			detail := models.ServiceDetail{Service: *svc, Related: related}

			if Format == "json" {
				return printJSON(detail)
			}

			fmt.Print(view.ServiceDetail(renderContext(), &detail))
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", defaultDetailLimit, "Maximum rows in each related section")
	cmd.Flags().BoolVar(&all, "all", false, "Show every related record")
	return cmd
}
