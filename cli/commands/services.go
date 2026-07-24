package commands

import (
	"context"
	"fmt"
	"sort"

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

			fmt.Printf("Service: %s\n", svc.EventSource)
			if svc.DisplayName != "" {
				fmt.Printf("Display Name: %s\n", svc.DisplayName)
			}
			if svc.Category != "" {
				fmt.Printf("Category: %s\n", svc.Category)
			}
			fmt.Printf("First Seen: %s\n", svc.FirstSeen)
			fmt.Printf("Last Seen: %s\n", svc.LastSeen)
			fmt.Printf("Total Events: %d\n", svc.TotalEvents)
			fmt.Printf("Roles: %d\n", svc.RolesCount)
			fmt.Printf("Resources: %d\n", svc.ResourcesCount)
			fmt.Printf("People: %d\n", svc.PeopleCount)
			fmt.Printf("Sessions: %d\n", svc.SessionsCount)
			fmt.Printf("Accounts: %d\n", svc.AccountsCount)

			if svc.TotalDeniedEvents > 0 {
				fmt.Printf("Denied Events: %d\n", svc.TotalDeniedEvents)
			}

			if len(svc.TopEventNames) > 0 {
				fmt.Println("\nTop Events:")
				svcEventKeys := make([]string, 0, len(svc.TopEventNames))
				for k := range svc.TopEventNames {
					svcEventKeys = append(svcEventKeys, k)
				}
				sort.Strings(svcEventKeys)
				for _, event := range svcEventKeys {
					fmt.Printf("  %s: %d\n", event, svc.TopEventNames[event])
				}
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&index, "index", 0, "Select service by list index (from 'services list')")

	return cmd
}
