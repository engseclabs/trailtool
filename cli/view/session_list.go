package view

import (
	"fmt"
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// SessionList renders the `sessions list` table with responsive columns (§6).
// Essential columns (SID WHEN USER ROLE EVENTS) are never dropped. Wide output
// adds account, client, role-session, tag, policy, type, duration, and lineage
// context. Role names shorten to their SSO permission-set name unless long is
// set (existing --long semantics preserved).
//
// sidWidth is the shortest unambiguous SID prefix for this list (from
// SidDisplayWidth); label resolves a person key to a display label. Context
// anchors the WHEN column's relative time (§4.5).
func SessionList(ctx render.Context, sessions []models.Session, sidWidth int, long bool, label func(string) string) string {
	if len(sessions) == 0 {
		return ctx.Empty("No sessions found.") + "\n"
	}

	// Collapsible-column policy by width (§6). Essential columns always show.
	showAccount := ctx.Width >= 100
	showType := ctx.Width >= 80
	showDuration := ctx.Width >= 80
	showChained := ctx.Width >= 100
	showSessionContext := ctx.Width >= 180

	cols := []render.Column{
		{Header: "SID", Align: render.AlignLeft},
		{Header: "WHEN", Align: render.AlignLeft},
		{Header: "USER", Align: render.AlignLeft},
		{Header: "ROLE", Align: render.AlignLeft},
	}
	if showAccount {
		cols = append(cols, render.Column{Header: "ACCOUNT", Align: render.AlignLeft})
	}
	cols = append(cols, render.Column{Header: "EVENTS", Align: render.AlignRight})
	if showSessionContext {
		cols = append(cols,
			render.Column{Header: "CLIENT", Align: render.AlignLeft},
			render.Column{Header: "SESSION NAME", Align: render.AlignLeft},
			render.Column{Header: "TAGS", Align: render.AlignLeft},
			render.Column{Header: "POLICY", Align: render.AlignLeft},
		)
	}
	if showType {
		cols = append(cols, render.Column{Header: "TYPE", Align: render.AlignLeft})
	}
	if showDuration {
		cols = append(cols, render.Column{Header: "DURATION", Align: render.AlignRight})
	}
	if showChained {
		cols = append(cols, render.Column{Header: "CHAINED", Align: render.AlignLeft})
	}

	t := render.NewTable(cols...)
	for i := range sessions {
		sess := &sessions[i]
		displayRole := sess.RoleName
		if !long {
			displayRole = ShortRoleName(sess.RoleName)
		}
		row := []string{
			ident(ctx, ShortSid(sess, sidWidth)),
			ctx.Style(render.Time, ctx.Relative(sess.StartTime)),
			label(sess.PersonKey),
			ident(ctx, displayRole),
		}
		if showAccount {
			row = append(row, sess.AccountID)
		}
		row = append(row, count(ctx, sess.EventsCount))
		if showSessionContext {
			row = append(row,
				optional(ctx, ctx.Truncate(topClientSummary(sess.Clients), 18)),
				optional(ctx, ctx.Truncate(sess.RoleSessionName, 20)),
				optional(ctx, ctx.Truncate(sessionTagsSummary(sess.SessionTags), 28)),
				sessionPolicySummary(ctx, sess),
			)
		}
		if showType {
			row = append(row, sess.DetectSessionType())
		}
		if showDuration {
			row = append(row, fmt.Sprintf("%dm", sess.DurationMinutes))
		}
		if showChained {
			row = append(row, ctx.Style(render.Muted, ChainedMarks(ctx, sess)))
		}
		t.Row(row...)
	}
	return ctx.RenderTable(t, 0)
}

func topClientSummary(clients []models.ClientAggregate) string {
	if len(clients) == 0 {
		return ""
	}
	sorted := append([]models.ClientAggregate(nil), clients...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].TotalEventCount != sorted[j].TotalEventCount {
			return sorted[i].TotalEventCount > sorted[j].TotalEventCount
		}
		return sorted[i].Key < sorted[j].Key
	})
	name := sorted[0].Name
	if name == "" {
		name = sorted[0].Category
	}
	if extra := len(sorted) - 1; extra > 0 {
		name += fmt.Sprintf(" +%d", extra)
	}
	return name
}

func sessionTagsSummary(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	summary := keys[0] + "=" + tags[keys[0]]
	if extra := len(keys) - 1; extra > 0 {
		summary += fmt.Sprintf(" +%d", extra)
	}
	return summary
}

func optional(ctx render.Context, value string) string {
	if strings.TrimSpace(value) == "" {
		return ctx.Style(render.Muted, "-")
	}
	return value
}

func sessionHasPolicy(sess *models.Session) bool {
	return sess.HasSessionPolicy || strings.TrimSpace(sess.SessionPolicy) != ""
}

func sessionPolicySummary(ctx render.Context, sess *models.Session) string {
	if sessionHasPolicy(sess) {
		return "yes"
	}
	return ctx.Style(render.Muted, "no")
}
