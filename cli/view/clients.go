package view

import (
	"fmt"
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

type compactClient struct {
	name     string
	requests int
	denied   int
	lastSeen string
	commands map[string]int
	sortKey  string
}

// Clients renders one glanceable row per client name. Aggregates split by
// version or platform are folded together because those diagnostics are
// available in VerboseClients and JSON.
func Clients(ctx render.Context, clients []models.ClientAggregate, hasEvents bool) string {
	if len(clients) == 0 {
		return emptyClients(ctx, hasEvents)
	}

	rows := compactClientRows(clients)
	table := render.NewTable(
		render.Column{Header: "CLIENT", Align: render.AlignLeft},
		render.Column{Header: "REQUESTS", Align: render.AlignRight},
		render.Column{Header: "DENIED", Align: render.AlignRight},
		render.Column{Header: "LAST USED", Align: render.AlignLeft},
		render.Column{Header: "COMMANDS", Align: render.AlignLeft},
	)
	for _, client := range rows {
		lastUsed := "-"
		if client.lastSeen != "" {
			lastUsed = ctx.Relative(client.lastSeen)
		}
		commands := topCommands(client.commands, 3)
		if commands == "" {
			commands = "-"
		}
		table.Row(
			ident(ctx, client.name),
			count(ctx, client.requests),
			denied(ctx, client.denied),
			ctx.Style(render.Time, lastUsed),
			commands,
		)
	}
	return ctx.Section(render.Heading("Clients", len(rows)), ctx.RenderTable(table, render.BodyIndent))
}

// VerboseClients retains version, platform, interval, and per-client API
// details for sessions detail --verbose.
func VerboseClients(ctx render.Context, clients []models.ClientAggregate, hasEvents bool) string {
	if len(clients) == 0 {
		return emptyClients(ctx, hasEvents)
	}

	sorted := make([]models.ClientAggregate, len(clients))
	copy(sorted, clients)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].TotalEventCount != sorted[j].TotalEventCount {
			return sorted[i].TotalEventCount > sorted[j].TotalEventCount
		}
		return sorted[i].Key < sorted[j].Key
	})

	var b strings.Builder
	for _, client := range sorted {
		b.WriteString(clientBlock(ctx, client))
	}
	return ctx.Section(render.Heading("Clients", len(sorted)), b.String())
}

func emptyClients(ctx render.Context, hasEvents bool) string {
	if !hasEvents {
		return ""
	}
	return ctx.Section(render.Heading("Clients", -1),
		"  "+ctx.Style(render.Muted, "none recorded (pre-cutover data, service-only traffic, or no accepted user agent)")+"\n")
}

func compactClientRows(clients []models.ClientAggregate) []compactClient {
	byName := make(map[string]*compactClient)
	for _, client := range clients {
		name := strings.TrimSpace(client.Name)
		if name == "" {
			name = strings.TrimSpace(client.Category)
		}
		if name == "" {
			name = "(unknown)"
		}
		key := strings.ToLower(name)
		row, ok := byName[key]
		if !ok {
			row = &compactClient{name: name, sortKey: key, commands: map[string]int{}}
			byName[key] = row
		} else if name < row.name {
			row.name = name
		}
		row.requests += client.TotalEventCount
		row.denied += client.DeniedEventCount
		if client.LastSeen > row.lastSeen {
			row.lastSeen = client.LastSeen
		}
		for command, commandCount := range client.Commands {
			if clientCommand, ok := strings.CutPrefix(command, "ua:"); ok {
				if clientCommand = strings.TrimSpace(clientCommand); clientCommand != "" {
					row.commands[clientCommand] += commandCount
				}
			}
		}
	}

	rows := make([]compactClient, 0, len(byName))
	for _, row := range byName {
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].requests != rows[j].requests {
			return rows[i].requests > rows[j].requests
		}
		return rows[i].sortKey < rows[j].sortKey
	})
	return rows
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
