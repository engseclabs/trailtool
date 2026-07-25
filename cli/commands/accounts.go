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
	return &cobra.Command{
		Use:   "detail <account-id>",
		Short: "Show account details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			accountID := args[0]
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
}
