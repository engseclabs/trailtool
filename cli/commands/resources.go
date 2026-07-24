package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

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
				return fatal("failed to connect to AWS: %v", err)
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

			if len(resources) == 0 {
				fmt.Println("No resources found.")
				return nil
			}

			if clickops {
				fmt.Printf("Found %d resources created/modified via web console:\n\n", len(resources))

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "#\tRESOURCE\tTYPE\tACCOUNT\tCLICKOPS EVENTS\tLAST SEEN")
				for i, r := range resources {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\n",
						i+1, r.Name, r.Type, r.AccountID, r.ClickOpsCount, r.LastSeen)
				}
				w.Flush()

				label := personLabels(ctx, s)
				fmt.Println("\n--- Console Operations ---")
				for _, r := range resources {
					fmt.Printf("\n%s (%s)\n", r.Name, r.Type)
					for _, access := range r.ClickOpsAccesses {
						date := access.AccessTime
						if len(date) >= 10 {
							date = date[:10]
						}
						fmt.Printf("  %s by %s (%dx) - %s\n",
							access.EventName, label(access.PersonKey), access.EventCount, date)
					}
				}
			} else {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "#\tRESOURCE\tTYPE\tACCOUNT\tEVENTS\tCLICKOPS\tLAST SEEN")
				for i, r := range resources {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n",
						i+1, r.Name, r.Type, r.AccountID, r.TotalEvents, r.ClickOpsCount, r.LastSeen)
				}
				w.Flush()
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&days, "days", 0, "Filter to last N days")
	cmd.Flags().StringVar(&serviceType, "service", "", "Filter by AWS service type (e.g. s3, lambda, ec2)")
	cmd.Flags().BoolVar(&clickops, "clickops", false, "Only show resources created/modified via web console")
	cmd.Flags().IntVar(&minClickOps, "min-clickops", 1, "Minimum ClickOps events (used with --clickops)")

	return cmd
}
