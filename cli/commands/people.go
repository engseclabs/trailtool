package commands

import (
	"context"
	"fmt"

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
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			people, err := s.ListPeople(ctx, CustomerID)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(people)
			}

			fmt.Print(view.People(renderContext(), people))
			return nil
		},
	}
}
