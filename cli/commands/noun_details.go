package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
)

const defaultDetailLimit = 10

func detailRelationLimit(cmd *cobra.Command, limit int, all bool) (int, error) {
	if all && cmd.Flags().Changed("limit") {
		return 0, fmt.Errorf("--all and --limit are mutually exclusive")
	}
	if limit < 1 {
		return 0, fmt.Errorf("--limit must be at least 1")
	}
	if all {
		return 0, nil
	}
	return limit, nil
}

func resolvePersonMatches(selector string, matches []models.Person) (*models.Person, error) {
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no person found with PID %q (check 'trailtool people list')", selector)
	case 1:
		return &matches[0], nil
	default:
		width := view.PersonIDDisplayWidth(matches)
		msg := fmt.Sprintf("%d people match PID %q: use a longer PID:\n", len(matches), selector)
		for i := range matches {
			msg += fmt.Sprintf("  %s  %s  %s\n",
				view.ShortPersonID(&matches[i], width),
				matches[i].DisplayLabel(),
				matches[i].PersonKey,
			)
		}
		return nil, fmt.Errorf("%s", msg)
	}
}

func resolveResourceMatches(selector string, matches []models.Resource) (*models.Resource, error) {
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no resource found with RID %q (check 'trailtool resources list')", selector)
	case 1:
		return &matches[0], nil
	default:
		width := view.ResourceIDDisplayWidth(matches)
		msg := fmt.Sprintf("%d resources match RID %q: use a longer RID:\n", len(matches), selector)
		for i := range matches {
			msg += fmt.Sprintf("  %s  %s  %s\n",
				view.ShortResourceID(&matches[i], width),
				matches[i].AccountID,
				matches[i].Identifier,
			)
		}
		return nil, fmt.Errorf("%s", msg)
	}
}
