package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/store"
)

func PeopleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "people",
		Short: "People tracked in CloudTrail",
	}
	cmd.AddCommand(peopleListCmd())
	cmd.AddCommand(peopleDetailCmd())
	return cmd
}

func peopleListCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
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
			people = capList(people, limit)

			if Format == "json" {
				return printJSON(people)
			}

			fmt.Print(view.People(renderContext(), people))
			return nil
		},
	}

	addListLimitFlag(cmd, &limit)
	return cmd
}

func peopleDetailCmd() *cobra.Command {
	var limit int
	var all bool
	var includeDeniedDetails bool

	cmd := &cobra.Command{
		Use:   "detail <pid>",
		Short: "Show person details",
		Long: `Show a person and their related activity using the PID from
'trailtool people list'. An unambiguous PID prefix is accepted.

Example:
  trailtool people detail 5nmama`,
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

			matches, err := s.FindPeopleByPIDPrefix(ctx, CustomerID, args[0])
			if err != nil {
				return fatal("%v", err)
			}
			person, err := resolvePersonMatches(args[0], matches)
			if err != nil {
				return fatal("%v", err)
			}

			related, err := s.LoadRelatedNouns(
				ctx,
				CustomerID,
				store.RelationKindPerson,
				person.PersonKey,
				relationLimit,
			)
			if err != nil {
				return fatal("%v", err)
			}
			person.ApplyRelationshipCounts(related.Counts)
			detail := models.PersonDetail{Person: *person, Related: related}

			if Format == "json" {
				return printJSON(detail)
			}

			fmt.Print(view.PersonDetail(renderContext(), &detail, includeDeniedDetails))
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", defaultDetailLimit, "Maximum rows in each related section")
	cmd.Flags().BoolVar(&all, "all", false, "Show every related record")
	cmd.Flags().BoolVar(&includeDeniedDetails, "include-denied-details", false, "Show denied event breakdowns")
	return cmd
}
