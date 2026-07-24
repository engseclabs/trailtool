package view

import (
	"fmt"
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// Clients renders the session's per-client user-agent aggregates as a section
// (§5.1): one block per client with identity (name/version/category), platform
// subtitle, reconciled request counts, first/last-seen interval, and top API
// events / client commands. Shipped semantics are preserved — only styling and
// width-awareness change.
//
// hasEvents reports whether the session recorded any events. An empty clients
// slice is ambiguous, not proof of no client: when the session has events but no
// aggregates, a muted note says so rather than silently omitting the section.
func Clients(ctx render.Context, clients []models.ClientAggregate, hasEvents bool) string {
	if len(clients) == 0 {
		if hasEvents {
			return ctx.Section(render.Heading("Clients", -1),
				"  "+ctx.Style(render.Muted, "none recorded (pre-cutover data, service-only traffic, or no accepted user agent)")+"\n")
		}
		return ""
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

	var b strings.Builder
	for _, c := range sorted {
		b.WriteString(clientBlock(ctx, c))
	}
	return ctx.Section(render.Heading("Clients", len(sorted)), b.String())
}

// clientBlock renders one client's block (indented two spaces).
func clientBlock(ctx render.Context, c models.ClientAggregate) string {
	name := c.Name
	if name == "" {
		name = "(unknown)"
	}
	head := name
	if c.Version != "" {
		head += " " + c.Version
	}

	var b strings.Builder

	// Identity line: name [version] [category]  N requests: M ok[, K denied][, S service-driven].
	// TotalEventCount includes denied — labeled "requests", deliberately distinct
	// from the session's success-only Events line, so no client shows more events
	// than its session (§5.1).
	ok := c.TotalEventCount - c.DeniedEventCount
	fmt.Fprintf(&b, "  %s  %s  %s requests: %s ok",
		ctx.Style(render.Ident, head),
		ctx.Style(render.Muted, "["+c.Category+"]"),
		ctx.Style(render.Count, n(c.TotalEventCount)),
		n(ok))
	if c.DeniedEventCount > 0 {
		fmt.Fprintf(&b, ", %s", ctx.Style(render.Denied, n(c.DeniedEventCount)+" denied"))
	}
	if c.ServiceDrivenEventCount > 0 {
		fmt.Fprintf(&b, ", %s service-driven", n(c.ServiceDrivenEventCount))
	}
	b.WriteByte('\n')

	if plat := clientPlatform(c); plat != "" {
		fmt.Fprintf(&b, "    %s\n", ctx.Style(render.Muted, plat))
	}
	if c.FirstSeen != "" || c.LastSeen != "" {
		fmt.Fprintf(&b, "    %s\n", ctx.Style(render.Time, "seen "+ctx.Interval(c.FirstSeen, c.LastSeen)))
	}

	// Commands mixes two namespaces: bare CloudTrail eventNames (the API calls AWS
	// recorded) and "ua:"-prefixed tokens the client's user-agent reported (its own
	// command surface). Show them as two separate labeled lists — different concepts
	// (§5.1); conflating them misleads.
	apiEvents, clientCmds := splitCommandNamespaces(c.Commands)
	if s := topCommands(apiEvents, 5); s != "" {
		fmt.Fprintf(&b, "    API events: %s\n", s)
	}
	if s := topCommands(clientCmds, 5); s != "" {
		fmt.Fprintf(&b, "    client commands: %s\n", s)
	}
	return b.String()
}

// splitCommandNamespaces separates a client's Commands map into bare CloudTrail
// eventNames and the "ua:"-prefixed user-agent command tokens (prefix stripped).
func splitCommandNamespaces(commands map[string]int) (apiEvents, clientCmds map[string]int) {
	apiEvents = map[string]int{}
	clientCmds = map[string]int{}
	for k, v := range commands {
		if cmd, ok := strings.CutPrefix(k, "ua:"); ok {
			clientCmds[cmd] = v
		} else {
			apiEvents[k] = v
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
