package view

import (
	"strconv"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// Standard-list rendering (§4). Lists expose stable selectors instead of row
// numbers. Headers are UPPERCASE and Header-styled by the table; numeric columns
// are right-aligned and a zero renders as "0". No result count is printed for
// plain lists, keeping them pipe-clean; empty results render a single Empty line
// instead of a header-only table.
//
// Views return the rendered string so they are golden-testable without AWS; the
// command layer prints the result.

// n formats an int for a right-aligned numeric cell.
func n(v int) string { return strconv.Itoa(v) }

// ident styles an identifier (email, role, resource id) with the Ident role.
func ident(ctx render.Context, s string) string { return ctx.Style(render.Ident, s) }

// count styles a numeric aggregate with the Count role.
func count(ctx render.Context, v int) string { return ctx.Style(render.Count, n(v)) }

// People renders the people list.
func People(ctx render.Context, people []models.Person) string {
	if len(people) == 0 {
		return ctx.Empty("No people found.") + "\n"
	}
	showWide := ctx.Width >= 100
	columns := []render.Column{
		{Header: "PID", Align: render.AlignLeft},
		{Header: "PERSON", Align: render.AlignLeft},
		{Header: "EVENTS", Align: render.AlignRight},
		{Header: "LAST SEEN", Align: render.AlignLeft},
	}
	if showWide {
		columns = append(columns,
			render.Column{Header: "SESSIONS", Align: render.AlignRight},
			render.Column{Header: "ROLES", Align: render.AlignRight},
			render.Column{Header: "ACCOUNTS", Align: render.AlignRight},
			render.Column{Header: "DENIED", Align: render.AlignRight},
		)
	}
	t := render.NewTable(columns...)
	pidWidth := PersonIDDisplayWidth(people)
	for i := range people {
		p := &people[i]
		row := []string{
			ident(ctx, shortID(p.PID(), pidWidth)),
			ident(ctx, p.DisplayLabel()),
			count(ctx, p.EventsCount),
			ctx.Style(render.Time, p.LastSeen),
		}
		if showWide {
			row = append(row,
				count(ctx, p.SessionsCount),
				count(ctx, p.RolesCount),
				count(ctx, p.AccountsCount),
				denied(ctx, p.DeniedEventCount),
			)
		}
		t.Row(row...)
	}
	return ctx.RenderTable(t, 0)
}

// Accounts renders the accounts list.
func Accounts(ctx render.Context, accounts []models.Account) string {
	if len(accounts) == 0 {
		return ctx.Empty("No accounts found.") + "\n"
	}
	showWide := ctx.Width >= 132
	showName := false
	for i := range accounts {
		showName = showName || accounts[i].AccountName != ""
	}
	columns := []render.Column{{Header: "ACCOUNT ID", Align: render.AlignLeft}}
	if showName {
		columns = append(columns, render.Column{Header: "NAME", Align: render.AlignLeft})
	}
	columns = append(columns,
		render.Column{Header: "EVENTS", Align: render.AlignRight},
		render.Column{Header: "LAST SEEN", Align: render.AlignLeft},
	)
	if showWide {
		columns = append(columns,
			render.Column{Header: "SESSIONS", Align: render.AlignRight},
			render.Column{Header: "PEOPLE", Align: render.AlignRight},
			render.Column{Header: "ROLES", Align: render.AlignRight},
			render.Column{Header: "SERVICES", Align: render.AlignRight},
			render.Column{Header: "RESOURCES", Align: render.AlignRight},
			render.Column{Header: "DENIED", Align: render.AlignRight},
		)
	}
	t := render.NewTable(columns...)
	for i := range accounts {
		a := &accounts[i]
		row := []string{ident(ctx, a.AccountID)}
		if showName {
			row = append(row, a.AccountName)
		}
		row = append(row,
			count(ctx, a.EventsCount),
			ctx.Style(render.Time, a.LastSeen),
		)
		if showWide {
			row = append(row,
				count(ctx, a.SessionsCount),
				count(ctx, a.PeopleCount),
				count(ctx, a.RolesCount),
				count(ctx, a.ServicesCount),
				count(ctx, a.ResourcesCount),
				denied(ctx, a.TotalDeniedEvents),
			)
		}
		t.Row(row...)
	}
	return ctx.RenderTable(t, 0)
}

// Roles renders the roles list. The DENIED column is styled Denied when nonzero
// so denied activity reads as such in mono/ASCII too; a zero stays a plain "0".
func Roles(ctx render.Context, roles []models.Role) string {
	if len(roles) == 0 {
		return ctx.Empty("No roles found.") + "\n"
	}
	showWide := ctx.Width >= 132
	columns := []render.Column{
		{Header: "ROLE ARN", Align: render.AlignLeft},
		{Header: "EVENTS", Align: render.AlignRight},
		{Header: "DENIED", Align: render.AlignRight},
		{Header: "LAST SEEN", Align: render.AlignLeft},
	}
	if showWide {
		columns = append(columns,
			render.Column{Header: "SESSIONS", Align: render.AlignRight},
			render.Column{Header: "PEOPLE", Align: render.AlignRight},
		)
	}
	t := render.NewTable(columns...)
	for i := range roles {
		r := &roles[i]
		row := []string{
			ident(ctx, r.ARN),
			count(ctx, r.TotalEvents),
			denied(ctx, r.TotalDeniedEvents),
			ctx.Style(render.Time, r.LastSeen),
		}
		if showWide {
			row = append(row,
				count(ctx, r.SessionsCount),
				count(ctx, r.PeopleCount),
			)
		}
		t.Row(row...)
	}
	return ctx.RenderTable(t, 0)
}

// Services renders the services list.
func Services(ctx render.Context, services []models.Service) string {
	if len(services) == 0 {
		return ctx.Empty("No services found.") + "\n"
	}
	showWide := ctx.Width >= 132
	columns := []render.Column{
		{Header: "EVENT SOURCE", Align: render.AlignLeft},
		{Header: "EVENTS", Align: render.AlignRight},
		{Header: "DENIED", Align: render.AlignRight},
		{Header: "LAST SEEN", Align: render.AlignLeft},
	}
	if showWide {
		columns = append(columns,
			render.Column{Header: "ROLES", Align: render.AlignRight},
			render.Column{Header: "RESOURCES", Align: render.AlignRight},
			render.Column{Header: "PEOPLE", Align: render.AlignRight},
			render.Column{Header: "SESSIONS", Align: render.AlignRight},
			render.Column{Header: "ACCOUNTS", Align: render.AlignRight},
		)
	}
	t := render.NewTable(columns...)
	for i := range services {
		svc := &services[i]
		row := []string{
			ident(ctx, svc.EventSource),
			count(ctx, svc.TotalEvents),
			denied(ctx, svc.TotalDeniedEvents),
			ctx.Style(render.Time, svc.LastSeen),
		}
		if showWide {
			row = append(row,
				count(ctx, svc.RolesCount),
				count(ctx, svc.ResourcesCount),
				count(ctx, svc.PeopleCount),
				count(ctx, svc.SessionsCount),
				count(ctx, svc.AccountsCount),
			)
		}
		t.Row(row...)
	}
	return ctx.RenderTable(t, 0)
}

// Resources renders the standard (non-ClickOps) resources list.
func Resources(ctx render.Context, resources []models.Resource) string {
	if len(resources) == 0 {
		return ctx.Empty("No resources found.") + "\n"
	}
	showWide := ctx.Width >= 132
	columns := []render.Column{
		{Header: "RID", Align: render.AlignLeft},
		{Header: "RESOURCE", Align: render.AlignLeft},
		{Header: "ACCOUNT", Align: render.AlignLeft},
		{Header: "EVENTS", Align: render.AlignRight},
		{Header: "LAST SEEN", Align: render.AlignLeft},
	}
	if showWide {
		columns = append(columns,
			render.Column{Header: "TYPE", Align: render.AlignLeft},
			render.Column{Header: "DENIED", Align: render.AlignRight},
			render.Column{Header: "CLICKOPS", Align: render.AlignRight},
			render.Column{Header: "ROLES", Align: render.AlignRight},
			render.Column{Header: "SESSIONS", Align: render.AlignRight},
		)
	}
	t := render.NewTable(columns...)
	ridWidth := ResourceIDDisplayWidth(resources)
	for i := range resources {
		r := &resources[i]
		resourceLabel := r.Identifier
		if resourceLabel == "" {
			resourceLabel = r.Name
		}
		row := []string{
			ident(ctx, shortID(r.RID(), ridWidth)),
			ident(ctx, resourceLabel),
			r.AccountID,
			count(ctx, r.TotalEvents),
			ctx.Style(render.Time, r.LastSeen),
		}
		if showWide {
			row = append(row,
				r.Type,
				denied(ctx, r.TotalDeniedEvents),
				clickops(ctx, r.ClickOpsCount),
				count(ctx, r.RolesCount),
				count(ctx, r.SessionsCount),
			)
		}
		t.Row(row...)
	}
	return ctx.RenderTable(t, 0)
}

// denied styles a denied-event count: Denied role plus a leading symbol accent
// when nonzero, a plain muted "0" when zero (a zero denied-count is meaningful
// signal, never blank — §4.4).
func denied(ctx render.Context, v int) string {
	if v == 0 {
		return ctx.Style(render.Muted, "0")
	}
	return ctx.Style(render.Denied, n(v))
}

// clickops styles a ClickOps count: Warn-accented when nonzero (ClickOps is the
// flagged concern), muted "0" when zero.
func clickops(ctx render.Context, v int) string {
	if v == 0 {
		return ctx.Style(render.Muted, "0")
	}
	return ctx.Style(render.Warn, n(v))
}
