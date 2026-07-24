package view

import (
	"fmt"
	"strings"
)

// ParseTagFilters parses a slice of "KEY=VALUE" strings into a map.
func ParseTagFilters(raw []string) (map[string]string, error) {
	result := make(map[string]string, len(raw))
	for _, kv := range raw {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			return nil, fmt.Errorf("invalid --tag %q: expected KEY=VALUE", kv)
		}
		result[kv[:idx]] = kv[idx+1:]
	}
	return result, nil
}

// SessionMatchesTags returns true when all filters are present and match in the session tags.
func SessionMatchesTags(sessionTags map[string]string, filters map[string]string) bool {
	for k, v := range filters {
		if sessionTags[k] != v {
			return false
		}
	}
	return true
}
