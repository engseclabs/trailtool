package commands

import "github.com/spf13/cobra"

// defaultListLimit bounds how many rows a `list` command prints by default.
// High-volume tables can hold tens of thousands of rows; the common call wants
// the most recent handful, not the whole table dumped to the terminal.
const defaultListLimit = 50

// addListLimitFlag registers the shared --limit flag on a list command. A limit
// of 0 means "no limit" (print everything). Negative values are rejected at use
// time by capList.
func addListLimitFlag(cmd *cobra.Command, limit *int) {
	cmd.Flags().IntVar(limit, "limit", defaultListLimit, "Maximum rows to show (0 for no limit)")
}

// capList truncates items to the first limit entries. limit <= 0 returns items
// unchanged (the --limit 0 "show everything" escape hatch). Callers sort before
// capping so the retained rows are the intended slice (newest-first for lists),
// not an arbitrary prefix.
func capList[T any](items []T, limit int) []T {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}
