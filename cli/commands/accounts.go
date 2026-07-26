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
	var limit int
	var filter nounListFilter

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all tracked AWS accounts",
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

			accounts, err := s.ListAccounts(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}
			accounts = filterNouns(accounts, normalized,
				func(account models.Account) string { return account.LastSeen },
				func(account models.Account) int { return account.TotalDeniedEvents })
			accounts = capList(accounts, limit)

			if Format == "json" {
				return printJSON(accounts)
			}

			fmt.Print(view.Accounts(renderContext(), accounts))
			return nil
		},
	}

	addNounListFilterFlags(cmd, &filter)
	addListLimitFlag(cmd, &limit)
	return cmd
}

func accountsDetailCmd() *cobra.Command {
	var limit int
	var all bool
	var includeDeniedDetails bool

	cmd := &cobra.Command{
		Use:   "detail <account-id>",
		Short: "Show account details",
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

			accountID := args[0]
			account, err := s.GetAccount(ctx, CustomerID, accountID)
			if err != nil {
				return fatal("%v", err)
			}
			if account == nil {
				return fatal("account not found: %s", accountID)
			}

			related, err := s.LoadRelatedNouns(
				ctx,
				CustomerID,
				store.RelationKindAccount,
				account.AccountID,
				relationLimit,
			)
			if err != nil {
				return fatal("%v", err)
			}
			account.ApplyRelationshipCounts(related.Counts)
			detail := models.AccountDetail{Account: *account, Related: related}

			if Format == "json" {
				return printJSON(detail)
			}

			fmt.Print(view.AccountDetail(renderContext(), &detail, includeDeniedDetails))
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", defaultDetailLimit, "Maximum rows in each related section")
	cmd.Flags().BoolVar(&all, "all", false, "Show every related record")
	cmd.Flags().BoolVar(&includeDeniedDetails, "include-denied-details", false, "Show denied event breakdowns")
	return cmd
}
