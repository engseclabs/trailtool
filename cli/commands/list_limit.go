package commands

import "github.com/spf13/cobra"

// defaultListLimit bounds how many rows a `list` command prints by default.
// High-volume tables can hold tens of thousands of rows; the common call wants
// the most recent handful, not the whole table dumped to the terminal.
const defaultListLimit = 50

// addListLimitFlag registers the shared --limit flag on a list command. A limit
// of 0 means "no limit" (print everything).
func addListLimitFlag(cmd *cobra.Command, limit *int) {
	cmd.Flags().IntVar(limit, "limit", defaultListLimit, "Maximum rows to show (0 for no limit)")
}

// capList truncates items to the first limit entries and normalizes nil to an
// empty slice for consistent JSON arrays. limit <= 0 keeps every item. Callers
// sort before capping so the retained rows are the intended slice.
func capList[T any](items []T, limit int) []T {
	if items == nil {
		return []T{}
	}
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}
