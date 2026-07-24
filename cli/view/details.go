package view

import (
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// Standard detail views (§5): Title + KV key-facts + per-section count-descending
// tables. Each is a pure render over an already-fetched model. Only rows with a
// meaningful value are added, matching the shipped detail output which omits
// empty/zero facts.

// AccountDetail renders the accounts detail view.
func AccountDetail(ctx render.Context, a *models.Account) string {
	var b strings.Builder
	b.WriteString(ctx.Title(ctx.Style(render.Ident, a.AccountID)))
	kv := render.NewKV()
	if a.AccountName != "" {
		kv.Add("Name", a.AccountName)
	}
	kv.Add("First Seen", ctx.Style(render.Time, a.FirstSeen))
	kv.Add("Last Seen", ctx.Style(render.Time, a.LastSeen))
	kv.Add("People", count(ctx, a.PeopleCount))
	kv.Add("Sessions", count(ctx, a.SessionsCount))
	kv.Add("Roles", count(ctx, a.RolesCount))
	kv.Add("Services", count(ctx, a.ServicesCount))
	kv.Add("Resources", count(ctx, a.ResourcesCount))
	kv.Add("Events", count(ctx, a.EventsCount))
	b.WriteString(ctx.RenderKV(kv, 0))
	return b.String()
}

// RoleDetail renders the roles detail view: facts, Services Used (alpha, as
// shipped), and Top Events (count-descending).
func RoleDetail(ctx render.Context, r *models.Role) string {
	var b strings.Builder
	b.WriteString(ctx.Title(ctx.Style(render.Ident, r.Name)))
	kv := render.NewKV().
		Add("ARN", ctx.Style(render.Ident, r.ARN)).
		Add("Account", r.AccountID).
		Add("First Seen", ctx.Style(render.Time, r.FirstSeen)).
		Add("Last Seen", ctx.Style(render.Time, r.LastSeen)).
		Add("Total Events", count(ctx, r.TotalEvents)).
		Add("People", count(ctx, r.PeopleCount)).
		Add("Sessions", count(ctx, r.SessionsCount))
	if r.TotalDeniedEvents > 0 {
		kv.Add("Denied Events", denied(ctx, r.TotalDeniedEvents))
	}
	b.WriteString(ctx.RenderKV(kv, 0))

	if len(r.ServicesUsed) > 0 {
		svcs := make([]string, len(r.ServicesUsed))
		copy(svcs, r.ServicesUsed)
		sort.Strings(svcs)
		var sb strings.Builder
		for _, svc := range svcs {
			sb.WriteString("  " + ctx.Style(render.Ident, svc) + "\n")
		}
		b.WriteString(ctx.Section(render.Heading("Services Used", len(svcs)), sb.String()))
	}

	b.WriteString(countTable(ctx, "Top Events", "EVENT", r.TopEventNames))
	return b.String()
}

// ServiceDetail renders the services detail view.
func ServiceDetail(ctx render.Context, svc *models.Service) string {
	var b strings.Builder
	b.WriteString(ctx.Title(ctx.Style(render.Ident, svc.EventSource)))
	kv := render.NewKV()
	if svc.DisplayName != "" {
		kv.Add("Display Name", svc.DisplayName)
	}
	if svc.Category != "" {
		kv.Add("Category", svc.Category)
	}
	kv.Add("First Seen", ctx.Style(render.Time, svc.FirstSeen))
	kv.Add("Last Seen", ctx.Style(render.Time, svc.LastSeen))
	kv.Add("Total Events", count(ctx, svc.TotalEvents))
	kv.Add("Roles", count(ctx, svc.RolesCount))
	kv.Add("Resources", count(ctx, svc.ResourcesCount))
	kv.Add("People", count(ctx, svc.PeopleCount))
	kv.Add("Sessions", count(ctx, svc.SessionsCount))
	kv.Add("Accounts", count(ctx, svc.AccountsCount))
	if svc.TotalDeniedEvents > 0 {
		kv.Add("Denied Events", denied(ctx, svc.TotalDeniedEvents))
	}
	b.WriteString(ctx.RenderKV(kv, 0))

	b.WriteString(countTable(ctx, "Top Events", "EVENT", svc.TopEventNames))
	return b.String()
}
