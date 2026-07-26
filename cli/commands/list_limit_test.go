package commands

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCapList(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}

	tests := map[string]struct {
		limit int
		want  []int
	}{
		"under limit returns all": {limit: 10, want: []int{1, 2, 3, 4, 5}},
		"exact limit returns all": {limit: 5, want: []int{1, 2, 3, 4, 5}},
		"over limit truncates":    {limit: 3, want: []int{1, 2, 3}},
		"zero means no limit":     {limit: 0, want: []int{1, 2, 3, 4, 5}},
		"negative means no limit": {limit: -1, want: []int{1, 2, 3, 4, 5}},
		"one keeps first only":    {limit: 1, want: []int{1}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := capList(items, tc.limit)
			if len(got) != len(tc.want) {
				t.Fatalf("capList(%v, %d) len = %d, want %d", items, tc.limit, len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("capList(%v, %d) = %v, want %v", items, tc.limit, got, tc.want)
				}
			}
		})
	}
}

func TestCapListEmpty(t *testing.T) {
	if got := capList([]int{}, 5); len(got) != 0 {
		t.Fatalf("capList on empty slice returned %v, want empty", got)
	}
	if got := capList[int](nil, 5); got == nil {
		t.Fatal("capList returned nil, want an empty JSON array")
	}
}

// TestListCommandsHaveLimitFlag asserts every list command registers --limit
// with the shared default, so the bound is uniform across nouns.
func TestListCommandsHaveLimitFlag(t *testing.T) {
	lists := map[string]*cobra.Command{
		"sessions list":  sessionsListCmd(),
		"roles list":     rolesListCmd(),
		"services list":  servicesListCmd(),
		"accounts list":  accountsListCmd(),
		"people list":    peopleListCmd(),
		"resources list": resourcesListCmd(),
	}
	for name, cmd := range lists {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flag("limit")
			if flag == nil {
				t.Fatalf("%s: --limit not registered", name)
			}
			if flag.DefValue != "50" {
				t.Fatalf("%s: --limit default = %q, want \"50\"", name, flag.DefValue)
			}
		})
	}
}

// TestSessionsListReverseFlagHelp guards the flipped default: --reverse now
// selects oldest-first, so its help must say so (the old text claimed the
// default was oldest-first).
func TestSessionsListReverseFlagHelp(t *testing.T) {
	flag := sessionsListCmd().Flag("reverse")
	if flag == nil {
		t.Fatal("sessions list: --reverse not registered")
	}
	if want := "oldest"; !strings.Contains(flag.Usage, want) {
		t.Fatalf("--reverse help = %q, want it to mention %q", flag.Usage, want)
	}
}
