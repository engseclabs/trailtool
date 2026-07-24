package view

import (
	"fmt"
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
)

// PrintClients renders the session's per-client user-agent aggregates: one block
// per client with identity (name/version), platform, event counts, first/last
// seen, and top commands. Silent when the session carries no clients (records
// ingested before client aggregation, or service-only traffic).
func PrintClients(clients []models.ClientAggregate) {
	if len(clients) == 0 {
		return
	}

	// Deterministic order: most active first, ties broken by key.
	sorted := make([]models.ClientAggregate, len(clients))
	copy(sorted, clients)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].TotalEventCount != sorted[j].TotalEventCount {
			return sorted[i].TotalEventCount > sorted[j].TotalEventCount
		}
		return sorted[i].Key < sorted[j].Key
	})

	fmt.Printf("\nClients (%d):\n", len(sorted))
	for _, c := range sorted {
		name := c.Name
		if name == "" {
			name = "(unknown)"
		}
		head := name
		if c.Version != "" {
			head += " " + c.Version
		}
		// TotalEventCount is all requests this client made, denied included —
		// deliberately distinct from the session's success-only "Events" line, so
		// we label it "requests" and break out the successful/denied split to
		// avoid a client showing more "events" than the session.
		ok := c.TotalEventCount - c.DeniedEventCount
		fmt.Printf("  %s  [%s]  %d requests: %d ok", head, c.Category, c.TotalEventCount, ok)
		if c.DeniedEventCount > 0 {
			fmt.Printf(", %d denied", c.DeniedEventCount)
		}
		if c.ServiceDrivenEventCount > 0 {
			fmt.Printf(", %d service-driven", c.ServiceDrivenEventCount)
		}
		fmt.Println()

		if plat := clientPlatform(c); plat != "" {
			fmt.Printf("    %s\n", plat)
		}
		if c.FirstSeen != "" || c.LastSeen != "" {
			fmt.Printf("    seen %s -> %s\n", c.FirstSeen, c.LastSeen)
		}
		// Commands mixes two namespaces: bare CloudTrail eventNames (the API calls
		// AWS recorded) and "ua:"-prefixed tokens the client's user-agent reported
		// (its own command surface, e.g. aws-cli's s3.cp). Show them separately —
		// they are different concepts and conflating them misleads.
		apiEvents, clientCmds := splitCommandNamespaces(c.Commands)
		if s := topCommands(apiEvents, 5); s != "" {
			fmt.Printf("    API events: %s\n", s)
		}
		if s := topCommands(clientCmds, 5); s != "" {
			fmt.Printf("    client commands: %s\n", s)
		}
	}
}

// splitCommandNamespaces separates a client's Commands map into bare CloudTrail
// eventNames and the "ua:"-prefixed user-agent command tokens (prefix stripped).
func splitCommandNamespaces(commands map[string]int) (apiEvents, clientCmds map[string]int) {
	apiEvents = map[string]int{}
	clientCmds = map[string]int{}
	for k, n := range commands {
		if cmd, ok := strings.CutPrefix(k, "ua:"); ok {
			clientCmds[cmd] = n
		} else {
			apiEvents[k] = n
		}
	}
	return apiEvents, clientCmds
}

// clientPlatform assembles the "os osversion · arch · runtime" subtitle from
// whichever platform fields the parser populated.
func clientPlatform(c models.ClientAggregate) string {
	var parts []string
	if os := strings.TrimSpace(c.OS + " " + c.OSVersion); os != "" {
		parts = append(parts, os)
	}
	if c.Architecture != "" {
		parts = append(parts, c.Architecture)
	}
	if c.Runtime != "" {
		parts = append(parts, c.Runtime)
	}
	return strings.Join(parts, " · ")
}

// topCommands renders the highest-count entries as "name (n)", limited to max,
// ties broken by name for stable output.
func topCommands(commands map[string]int, max int) string {
	if len(commands) == 0 {
		return ""
	}
	keys := make([]string, 0, len(commands))
	for k := range commands {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if commands[keys[i]] != commands[keys[j]] {
			return commands[keys[i]] > commands[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > max {
		keys = keys[:max]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s (%d)", k, commands[k]))
	}
	return strings.Join(parts, ", ")
}
