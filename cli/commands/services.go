package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
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
	var index int

	cmd := &cobra.Command{
		Use:   "detail [event-source]",
		Short: "Show service details",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && index == 0 {
				return fatal("event-source argument or --index is required")
			}
			if len(args) > 0 && index != 0 {
				return fatal("event-source argument and --index are mutually exclusive")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			var eventSource string
			if index != 0 {
				services, listErr := s.ListServices(ctx, CustomerID)
				if listErr != nil {
					return fatal("%v", listErr)
				}
				if index < 1 || index > len(services) {
					return fatal("--index %d out of range (1-%d)", index, len(services))
				}
				eventSource = services[index-1].EventSource
			} else {
				eventSource = args[0]
			}

			svc, err := s.GetService(ctx, CustomerID, eventSource)
			if err != nil {
				return fatal("%v", err)
			}
			if svc == nil {
				return fatal("service not found: %s", eventSource)
			}

			if Format == "json" {
				return printJSON(svc)
			}

			fmt.Print(view.ServiceDetail(renderContext(), svc))
			return nil
		},
	}

	cmd.Flags().IntVar(&index, "index", 0, "Select service by list index (from 'services list')")

	return cmd
}
