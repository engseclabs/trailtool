package view

import (
	"strconv"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// Standard-list rendering (§5). Each list is one render.Table with a leading `#`
// index column (rows stay addressable by index for detail commands — a hard
// constraint, §8). Headers are UPPERCASE and Header-styled by the table; numeric
// columns are right-aligned and a zero renders as "0" (§4.4). No result count is
// printed for plain lists, keeping them pipe-clean; empty results render a single
// Empty line instead of a header-only table (§5).
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
	t := render.NewTable(
		render.Column{Header: "#", Align: render.AlignRight},
		render.Column{Header: "PERSON", Align: render.AlignLeft},
		render.Column{Header: "KEY", Align: render.AlignLeft},
		render.Column{Header: "SESSIONS", Align: render.AlignRight},
		render.Column{Header: "ROLES", Align: render.AlignRight},
		render.Column{Header: "ACCOUNTS", Align: render.AlignRight},
		render.Column{Header: "LAST SEEN", Align: render.AlignLeft},
	)
	for i := range people {
		p := &people[i]
		t.Row(
			n(i+1),
			ident(ctx, p.DisplayLabel()),
			ShortPersonKey(p.PersonKey),
			count(ctx, p.SessionsCount),
			count(ctx, p.RolesCount),
			count(ctx, p.AccountsCount),
			ctx.Style(render.Time, p.LastSeen),
		)
	}
	return ctx.RenderTable(t, 0)
}

// Accounts renders the accounts list.
func Accounts(ctx render.Context, accounts []models.Account) string {
	if len(accounts) == 0 {
		return ctx.Empty("No accounts found.") + "\n"
	}
	t := render.NewTable(
		render.Column{Header: "#", Align: render.AlignRight},
		render.Column{Header: "ACCOUNT ID", Align: render.AlignLeft},
		render.Column{Header: "NAME", Align: render.AlignLeft},
		render.Column{Header: "PEOPLE", Align: render.AlignRight},
		render.Column{Header: "SESSIONS", Align: render.AlignRight},
		render.Column{Header: "ROLES", Align: render.AlignRight},
		render.Column{Header: "SERVICES", Align: render.AlignRight},
		render.Column{Header: "RESOURCES", Align: render.AlignRight},
		render.Column{Header: "LAST SEEN", Align: render.AlignLeft},
	)
	for i := range accounts {
		a := &accounts[i]
		t.Row(
			n(i+1),
			ident(ctx, a.AccountID),
			a.AccountName,
			count(ctx, a.PeopleCount),
			count(ctx, a.SessionsCount),
			count(ctx, a.RolesCount),
			count(ctx, a.ServicesCount),
			count(ctx, a.ResourcesCount),
			ctx.Style(render.Time, a.LastSeen),
		)
	}
	return ctx.RenderTable(t, 0)
}

// Roles renders the roles list. The DENIED column is styled Denied when nonzero
// so denied activity reads as such in mono/ASCII too; a zero stays a plain "0".
func Roles(ctx render.Context, roles []models.Role) string {
	if len(roles) == 0 {
		return ctx.Empty("No roles found.") + "\n"
	}
	t := render.NewTable(
		render.Column{Header: "#", Align: render.AlignRight},
		render.Column{Header: "NAME", Align: render.AlignLeft},
		render.Column{Header: "ACCOUNT", Align: render.AlignLeft},
		render.Column{Header: "EVENTS", Align: render.AlignRight},
		render.Column{Header: "PEOPLE", Align: render.AlignRight},
		render.Column{Header: "SESSIONS", Align: render.AlignRight},
		render.Column{Header: "DENIED", Align: render.AlignRight},
		render.Column{Header: "LAST SEEN", Align: render.AlignLeft},
	)
	for i := range roles {
		r := &roles[i]
		t.Row(
			n(i+1),
			ident(ctx, r.Name),
			r.AccountID,
			count(ctx, r.TotalEvents),
			count(ctx, r.PeopleCount),
			count(ctx, r.SessionsCount),
			denied(ctx, r.TotalDeniedEvents),
			ctx.Style(render.Time, r.LastSeen),
		)
	}
	return ctx.RenderTable(t, 0)
}

// Services renders the services list.
func Services(ctx render.Context, services []models.Service) string {
	if len(services) == 0 {
		return ctx.Empty("No services found.") + "\n"
	}
	t := render.NewTable(
		render.Column{Header: "#", Align: render.AlignRight},
		render.Column{Header: "SERVICE", Align: render.AlignLeft},
		render.Column{Header: "DISPLAY NAME", Align: render.AlignLeft},
		render.Column{Header: "EVENTS", Align: render.AlignRight},
		render.Column{Header: "ROLES", Align: render.AlignRight},
		render.Column{Header: "RESOURCES", Align: render.AlignRight},
		render.Column{Header: "PEOPLE", Align: render.AlignRight},
		render.Column{Header: "LAST SEEN", Align: render.AlignLeft},
	)
	for i := range services {
		svc := &services[i]
		t.Row(
			n(i+1),
			ident(ctx, svc.EventSource),
			svc.DisplayName,
			count(ctx, svc.TotalEvents),
			count(ctx, svc.RolesCount),
			count(ctx, svc.ResourcesCount),
			count(ctx, svc.PeopleCount),
			ctx.Style(render.Time, svc.LastSeen),
		)
	}
	return ctx.RenderTable(t, 0)
}

// Resources renders the standard (non-ClickOps) resources list.
func Resources(ctx render.Context, resources []models.Resource) string {
	if len(resources) == 0 {
		return ctx.Empty("No resources found.") + "\n"
	}
	t := render.NewTable(
		render.Column{Header: "#", Align: render.AlignRight},
		render.Column{Header: "RESOURCE", Align: render.AlignLeft},
		render.Column{Header: "TYPE", Align: render.AlignLeft},
		render.Column{Header: "ACCOUNT", Align: render.AlignLeft},
		render.Column{Header: "EVENTS", Align: render.AlignRight},
		render.Column{Header: "CLICKOPS", Align: render.AlignRight},
		render.Column{Header: "LAST SEEN", Align: render.AlignLeft},
	)
	for i := range resources {
		r := &resources[i]
		t.Row(
			n(i+1),
			ident(ctx, r.Name),
			r.Type,
			r.AccountID,
			count(ctx, r.TotalEvents),
			clickops(ctx, r.ClickOpsCount),
			ctx.Style(render.Time, r.LastSeen),
		)
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
