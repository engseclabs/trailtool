package view

import (
	"fmt"
	"time"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// SessionList renders the `sessions list` table with responsive columns (§6).
// Essential columns (SID WHEN USER ROLE EVENTS) are never dropped; collapsible
// columns (ACCOUNT TYPE DURATION CHAINED) drop below width thresholds so narrow
// terminals stay readable. Role names shorten to their SSO permission-set name
// unless long is set (existing --long semantics preserved).
//
// sidWidth is the shortest unambiguous SID prefix for this list (from
// SidDisplayWidth); label resolves a person key to a display label. now anchors
// the WHEN column's relative time (§4.5), injected so tests are deterministic.
func SessionList(ctx render.Context, sessions []models.Session, sidWidth int, long bool, label func(string) string, now time.Time) string {
	if len(sessions) == 0 {
		return ctx.Empty("No sessions found.") + "\n"
	}

	// Collapsible-column policy by width (§6). Essential columns always show.
	showAccount := ctx.Width >= 100
	showType := ctx.Width >= 80
	showDuration := ctx.Width >= 80
	showChained := ctx.Width >= 100

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
			ctx.Style(render.Time, render.Relative(sess.StartTime, now)),
			label(sess.PersonKey),
			ident(ctx, displayRole),
		}
		if showAccount {
			row = append(row, sess.AccountID)
		}
		row = append(row, count(ctx, sess.EventsCount))
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
