package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

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
	var limit int
	var filter nounListFilter
	var category string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all tracked AWS services",
		RunE: func(cmd *cobra.Command, args []string) error {
			normalized, err := filter.normalize(time.Now())
			if err != nil {
				return fatal("%v", err)
			}
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			services, err := s.ListServices(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}
			services = filterNouns(services, normalized,
				func(service models.Service) string { return service.LastSeen },
				func(service models.Service) int { return service.TotalDeniedEvents })
			if category != "" {
				filtered := services[:0]
				for _, service := range services {
					if strings.EqualFold(service.Category, category) {
						filtered = append(filtered, service)
					}
				}
				services = filtered
			}
			services = capList(services, limit)

			if Format == "json" {
				return printJSON(services)
			}

			fmt.Print(view.Services(renderContext(), services))
			return nil
		},
	}

	addNounListFilterFlags(cmd, &filter)
	cmd.Flags().StringVar(&category, "category", "", "Only show services in this category")
	addListLimitFlag(cmd, &limit)
	return cmd
}

func servicesDetailCmd() *cobra.Command {
	var limit int
	var all bool
	var includeDeniedDetails bool

	cmd := &cobra.Command{
		Use:   "detail <event-source>",
		Short: "Show service details",
		Long: `Show service details by canonical CloudTrail event source.
A bare name such as "s3" is also tried as "s3.amazonaws.com"; semantic aliases
such as "ses" for "email.amazonaws.com" are not inferred.`,
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
			svc.ApplyRelationshipCounts(related.Counts)
			detail := models.ServiceDetail{Service: *svc, Related: related}

			if Format == "json" {
				return printJSON(detail)
			}

			fmt.Print(view.ServiceDetail(renderContext(), &detail, includeDeniedDetails))
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", defaultDetailLimit, "Maximum rows in each related section")
	cmd.Flags().BoolVar(&all, "all", false, "Show every related record")
	cmd.Flags().BoolVar(&includeDeniedDetails, "include-denied-details", false, "Show denied event breakdowns")
	return cmd
}
