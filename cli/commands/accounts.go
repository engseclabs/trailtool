package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

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
				return fatal("failed to connect to AWS: %v", err)
			}

			accounts, err := s.ListAccounts(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(accounts)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tACCOUNT ID\tNAME\tPEOPLE\tSESSIONS\tROLES\tSERVICES\tRESOURCES\tLAST SEEN")
			for i, a := range accounts {
				fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
					i+1, a.AccountID, a.AccountName, a.PeopleCount, a.SessionsCount,
					a.RolesCount, a.ServicesCount, a.ResourcesCount, a.LastSeen)
			}
			return w.Flush()
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
				return fatal("failed to connect to AWS: %v", err)
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

			fmt.Printf("Account: %s\n", account.AccountID)
			if account.AccountName != "" {
				fmt.Printf("Name: %s\n", account.AccountName)
			}
			fmt.Printf("First Seen: %s\n", account.FirstSeen)
			fmt.Printf("Last Seen: %s\n", account.LastSeen)
			fmt.Printf("People: %d\n", account.PeopleCount)
			fmt.Printf("Sessions: %d\n", account.SessionsCount)
			fmt.Printf("Roles: %d\n", account.RolesCount)
			fmt.Printf("Services: %d\n", account.ServicesCount)
			fmt.Printf("Resources: %d\n", account.ResourcesCount)
			fmt.Printf("Events: %d\n", account.EventsCount)

			return nil
		},
	}

	cmd.Flags().IntVar(&index, "index", 0, "Select account by list index (from 'accounts list')")

	return cmd
}
