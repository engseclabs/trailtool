package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

type nounListFilter struct {
	days      int
	after     string
	before    string
	hasDenied bool
}

type normalizedNounListFilter struct {
	after     string
	before    string
	hasDenied bool
}

func addNounListFilterFlags(cmd *cobra.Command, filter *nounListFilter) {
	cmd.Flags().IntVar(&filter.days, "days", 0, "Only show nouns last seen in the last N days; activity totals remain lifetime totals")
	cmd.Flags().StringVar(&filter.after, "after", "", "Only show nouns last seen at or after this time (RFC3339); activity totals remain lifetime totals")
	cmd.Flags().StringVar(&filter.before, "before", "", "Only show nouns last seen before this time (RFC3339); activity totals remain lifetime totals")
	cmd.Flags().BoolVar(&filter.hasDenied, "has-denied", false, "Only show nouns with denied activity")
}

func (filter nounListFilter) normalize(now time.Time) (normalizedNounListFilter, error) {
	if filter.days < 0 {
		return normalizedNounListFilter{}, fmt.Errorf("--days must be at least 0")
	}
	if filter.days > 0 && filter.after != "" {
		return normalizedNounListFilter{}, fmt.Errorf("--days and --after are mutually exclusive")
	}

	after := filter.after
	if filter.days > 0 {
		after = now.UTC().AddDate(0, 0, -filter.days).Format(time.RFC3339)
	}
	afterTime, err := parseFilterTime("--after", after)
	if err != nil {
		return normalizedNounListFilter{}, err
	}
	beforeTime, err := parseFilterTime("--before", filter.before)
	if err != nil {
		return normalizedNounListFilter{}, err
	}
	if !afterTime.IsZero() && !beforeTime.IsZero() && !afterTime.Before(beforeTime) {
		return normalizedNounListFilter{}, fmt.Errorf("--after must be earlier than --before")
	}

	normalized := normalizedNounListFilter{hasDenied: filter.hasDenied}
	if !afterTime.IsZero() {
		normalized.after = afterTime.Format(time.RFC3339)
	}
	if !beforeTime.IsZero() {
		normalized.before = beforeTime.Format(time.RFC3339)
	}
	return normalized, nil
}

func parseFilterTime(flag, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s %q: use RFC3339", flag, value)
	}
	return parsed.UTC(), nil
}

func filterNouns[T any](
	items []T,
	filter normalizedNounListFilter,
	lastSeen func(T) string,
	deniedCount func(T) int,
) []T {
	filtered := items[:0]
	for _, item := range items {
		seen := lastSeen(item)
		if filter.after != "" && seen < filter.after {
			continue
		}
		if filter.before != "" && seen >= filter.before {
			continue
		}
		if filter.hasDenied && deniedCount(item) == 0 {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}
