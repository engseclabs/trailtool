package view

import (
	"fmt"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// ClickOps renders the two-level ClickOps report (§5): a summary Table of the
// resources touched via the web console, followed by a Console Operations section
// grouping each resource's console events. ClickOps counts are Warn-accented (the
// flagged concern). The report keeps its existing "Found N …" preamble — the one
// list that prints a count by design.
//
// label resolves a person key to a display label (passed in so the view stays
// store-free).
func ClickOps(ctx render.Context, resources []models.Resource, label func(string) string) string {
	if len(resources) == 0 {
		return ctx.Empty("No resources found.") + "\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", ctx.Style(render.Warn,
		fmt.Sprintf("Found %d resources created/modified via web console:", len(resources))))

	t := render.NewTable(
		render.Column{Header: "#", Align: render.AlignRight},
		render.Column{Header: "RESOURCE", Align: render.AlignLeft},
		render.Column{Header: "TYPE", Align: render.AlignLeft},
		render.Column{Header: "ACCOUNT", Align: render.AlignLeft},
		render.Column{Header: "CLICKOPS EVENTS", Align: render.AlignRight},
		render.Column{Header: "LAST SEEN", Align: render.AlignLeft},
	)
	for i := range resources {
		r := &resources[i]
		t.Row(
			n(i+1),
			ident(ctx, r.Name),
			r.Type,
			r.AccountID,
			clickops(ctx, r.ClickOpsCount),
			ctx.Style(render.Time, r.LastSeen),
		)
	}
	b.WriteString(ctx.RenderTable(t, 0))

	var ops strings.Builder
	for i := range resources {
		r := &resources[i]
		fmt.Fprintf(&ops, "\n%s %s\n", ident(ctx, r.Name), ctx.Style(render.Muted, "("+r.Type+")"))
		for _, access := range r.ClickOpsAccesses {
			date := access.AccessTime
			if len(date) >= 10 {
				date = date[:10]
			}
			fmt.Fprintf(&ops, "  %s by %s %s - %s\n",
				access.EventName,
				label(access.PersonKey),
				ctx.Style(render.Warn, fmt.Sprintf("(%dx)", access.EventCount)),
				ctx.Style(render.Time, date))
		}
	}
	b.WriteString(ctx.Section(render.Heading("Console Operations", -1), ops.String()))
	return b.String()
}
