package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/store"
)

func AccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "AWS accounts",
	}
	cmd.AddCommand(accountsListCmd())
	cmd.AddCommand(accountsDetailCmd())
	return cmd
}

func accountsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked AWS accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			accounts, err := s.ListAccounts(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(accounts)
			}

			fmt.Print(view.Accounts(renderContext(), accounts))
			return nil
		},
	}
}

func accountsDetailCmd() *cobra.Command {
	var index int

	cmd := &cobra.Command{
		Use:   "detail [account-id]",
		Short: "Show account details",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && index == 0 {
				return fatal("account-id argument or --index is required")
			}
			if len(args) > 0 && index != 0 {
				return fatal("account-id argument and --index are mutually exclusive")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			var accountID string
			if index != 0 {
				accounts, listErr := s.ListAccounts(ctx, CustomerID)
				if listErr != nil {
					return fatal("%v", listErr)
				}
				if index < 1 || index > len(accounts) {
					return fatal("--index %d out of range (1-%d)", index, len(accounts))
				}
				accountID = accounts[index-1].AccountID
			} else {
				accountID = args[0]
			}

			account, err := s.GetAccount(ctx, CustomerID, accountID)
			if err != nil {
				return fatal("%v", err)
			}
			if account == nil {
				return fatal("account not found: %s", accountID)
			}

			if Format == "json" {
				return printJSON(account)
			}

			fmt.Print(view.AccountDetail(renderContext(), account))
			return nil
		},
	}

	cmd.Flags().IntVar(&index, "index", 0, "Select account by list index (from 'accounts list')")

	return cmd
}
