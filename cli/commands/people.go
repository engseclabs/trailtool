package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/store"
)

func PeopleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "people",
		Short: "People tracked in CloudTrail",
	}
	cmd.AddCommand(peopleListCmd())
	return cmd
}

func peopleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked people",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			people, err := s.ListPeople(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(people)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tPERSON\tKEY\tSESSIONS\tROLES\tACCOUNTS\tLAST SEEN")
			for i, p := range people {
				fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%s\n",
					i+1, p.DisplayLabel(), view.ShortPersonKey(p.PersonKey), p.SessionsCount, p.RolesCount, p.AccountsCount, p.LastSeen)
			}
			return w.Flush()
		},
	}
}
