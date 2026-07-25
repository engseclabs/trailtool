package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
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

	cmd := &cobra.Command{
		Use:   "detail <role-arn-or-name>",
		Short: "Show role details",
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
				return fatal("role not found")
			}

			if Format == "json" {
				return printJSON(role)
			}

			fmt.Print(view.RoleDetail(renderContext(), role))
			return nil
		},
	}

	cmd.Flags().StringVar(&accountID, "account", "", "Filter by AWS account ID (disambiguates roles with the same name)")

	return cmd
}

func rolesPolicyCmd() *cobra.Command {
	var includeDenied bool
	var explain bool
	var accountID string

	cmd := &cobra.Command{
		Use:   "policy <role-arn-or-name>",
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
