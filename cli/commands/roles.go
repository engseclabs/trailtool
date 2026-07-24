package commands

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/policy"
	"github.com/engseclabs/trailtool/core/store"
)

func RolesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "IAM roles",
	}
	cmd.AddCommand(rolesListCmd())
	cmd.AddCommand(rolesDetailCmd())
	cmd.AddCommand(rolesPolicyCmd())
	return cmd
}

func rolesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked IAM roles",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			roles, err := s.ListRoles(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(roles)
			}

			fmt.Print(view.Roles(renderContext(), roles))
			return nil
		},
	}
}

func rolesDetailCmd() *cobra.Command {
	var accountID string
	var index int

	cmd := &cobra.Command{
		Use:   "detail [role-name-or-arn]",
		Short: "Show role details",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && index == 0 {
				return fatal("role-name-or-arn argument or --index is required")
			}
			if len(args) > 0 && index != 0 {
				return fatal("role-name-or-arn argument and --index are mutually exclusive")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			var role *models.Role
			if index != 0 {
				roles, listErr := s.ListRoles(ctx, CustomerID)
				if listErr != nil {
					return fatal("%v", listErr)
				}
				if index < 1 || index > len(roles) {
					return fatal("--index %d out of range (1-%d)", index, len(roles))
				}
				role, err = lookupRole(ctx, s, roles[index-1].ARN, accountID)
			} else {
				role, err = lookupRole(ctx, s, args[0], accountID)
			}
			if err != nil {
				return fatal("%v", err)
			}
			if role == nil {
				return fatal("role not found")
			}

			if Format == "json" {
				return printJSON(role)
			}

			fmt.Printf("Role: %s\n", role.Name)
			fmt.Printf("ARN: %s\n", role.ARN)
			fmt.Printf("Account: %s\n", role.AccountID)
			fmt.Printf("First Seen: %s\n", role.FirstSeen)
			fmt.Printf("Last Seen: %s\n", role.LastSeen)
			fmt.Printf("Total Events: %d\n", role.TotalEvents)
			fmt.Printf("People: %d\n", role.PeopleCount)
			fmt.Printf("Sessions: %d\n", role.SessionsCount)

			if role.TotalDeniedEvents > 0 {
				fmt.Printf("Denied Events: %d\n", role.TotalDeniedEvents)
			}

			if len(role.ServicesUsed) > 0 {
				fmt.Println("\nServices Used:")
				sortedSvcs := make([]string, len(role.ServicesUsed))
				copy(sortedSvcs, role.ServicesUsed)
				sort.Strings(sortedSvcs)
				for _, svc := range sortedSvcs {
					fmt.Printf("  %s\n", svc)
				}
			}

			if len(role.TopEventNames) > 0 {
				fmt.Println("\nTop Events:")
				roleEventKeys := make([]string, 0, len(role.TopEventNames))
				for k := range role.TopEventNames {
					roleEventKeys = append(roleEventKeys, k)
				}
				sort.Strings(roleEventKeys)
				for _, event := range roleEventKeys {
					fmt.Printf("  %s: %d\n", event, role.TopEventNames[event])
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&accountID, "account", "", "Filter by AWS account ID (disambiguates roles with the same name)")
	cmd.Flags().IntVar(&index, "index", 0, "Select role by list index (from 'roles list')")

	return cmd
}

func rolesPolicyCmd() *cobra.Command {
	var includeDenied bool
	var explain bool
	var accountID string

	cmd := &cobra.Command{
		Use:   "policy [role-name-or-arn]",
		Short: "Generate least-privilege IAM policy for a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			role, err := lookupRole(ctx, s, args[0], accountID)
			if err != nil {
				return fatal("%v", err)
			}
			if role == nil {
				return fatal("role not found: %s", args[0])
			}

			result, err := policy.GeneratePolicy(role, includeDenied)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(result)
			}

			fmt.Println(result.PolicyJSON)

			if explain {
				fmt.Fprintf(os.Stderr, "\n--- Policy Summary ---\n")
				fmt.Fprintf(os.Stderr, "Role: %s (%s)\n", result.RoleName, result.RoleARN)
				fmt.Fprintf(os.Stderr, "Total unique IAM actions: %d\n", result.TotalActionsUsed)
				if len(result.UnmappedEvents) > 0 {
					fmt.Fprintf(os.Stderr, "Unmapped CloudTrail events: %d\n", len(result.UnmappedEvents))
					for _, e := range result.UnmappedEvents {
						fmt.Fprintf(os.Stderr, "  - %s\n", e)
					}
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&includeDenied, "include-denied", false, "Include denied events in policy")
	cmd.Flags().BoolVar(&explain, "explain", false, "Show policy explanation on stderr")
	cmd.Flags().StringVar(&accountID, "account", "", "Filter by AWS account ID (disambiguates roles with the same name)")

	return cmd
}
