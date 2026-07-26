package commands

import (
	"testing"
	"time"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/spf13/cobra"
)

func TestNounListFilterUsesRollingWindowAndExclusiveBefore(t *testing.T) {
	filter, err := (nounListFilter{
		days:      7,
		before:    "2026-07-25T00:00:00Z",
		hasDenied: true,
	}).normalize(time.Date(2026, 7, 24, 15, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if filter.after != "2026-07-17T15:30:00Z" {
		t.Fatalf("after = %q", filter.after)
	}

	resources := []models.Resource{
		{Identifier: "unobserved", TotalDeniedEvents: 1},
		{Identifier: "before", LastSeen: "2026-07-17T15:29:59Z", TotalDeniedEvents: 1},
		{Identifier: "allowed", LastSeen: "2026-07-20T00:00:00Z"},
		{Identifier: "match", LastSeen: "2026-07-24T23:59:59Z", TotalDeniedEvents: 1},
		{Identifier: "at-before", LastSeen: "2026-07-25T00:00:00Z", TotalDeniedEvents: 1},
	}
	got := filterNouns(resources, filter,
		func(resource models.Resource) string { return resource.LastSeen },
		func(resource models.Resource) int { return resource.TotalDeniedEvents })
	if len(got) != 1 || got[0].Identifier != "match" {
		t.Fatalf("filtered resources = %#v", got)
	}
}

func TestNounListFilterValidation(t *testing.T) {
	now := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	tests := []nounListFilter{
		{days: -1},
		{days: 1, after: "2026-07-20T00:00:00Z"},
		{after: "not-a-time"},
		{after: "2026-07-25T00:00:00Z", before: "2026-07-24T00:00:00Z"},
	}
	for _, filter := range tests {
		if _, err := filter.normalize(now); err == nil {
			t.Fatalf("filter %#v was accepted", filter)
		}
	}
}

func TestAggregateListCommandsExposeCommonFilters(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"people":    peopleListCmd(),
		"roles":     rolesListCmd(),
		"accounts":  accountsListCmd(),
		"services":  servicesListCmd(),
		"resources": resourcesListCmd(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, flag := range []string{"days", "after", "before", "has-denied"} {
				if cmd.Flag(flag) == nil {
					t.Fatalf("%s list is missing --%s", name, flag)
				}
			}
		})
	}
}
