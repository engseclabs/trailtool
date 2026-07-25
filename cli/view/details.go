package view

import (
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// Standard detail views (§5): Title + KV key-facts + per-section count-descending
// tables. Each is a pure render over an already-fetched model. Only rows with a
// meaningful value are added, matching the shipped detail output which omits
// empty/zero facts.

// AccountDetail renders account activity and exact relationships.
func AccountDetail(ctx render.Context, detail *models.AccountDetail) string {
	a := &detail.Account
	var b strings.Builder
	b.WriteString(ctx.Title(ctx.Style(render.Ident, a.AccountID)))
	kv := render.NewKV()
	if a.AccountName != "" {
		kv.Add("Name", a.AccountName)
	}
	kv.Add("First Seen", ctx.Style(render.Time, a.FirstSeen)).
		Add("Last Seen", ctx.Style(render.Time, a.LastSeen)).
		Add("Events", count(ctx, a.EventsCount)).
		Add("People", count(ctx, a.PeopleCount)).
		Add("Sessions", count(ctx, a.SessionsCount)).
		Add("Roles", count(ctx, a.RolesCount)).
		Add("Services", count(ctx, a.ServicesCount)).
		Add("Resources", count(ctx, a.ResourcesCount))
	if a.TotalDeniedEvents > 0 {
		kv.Add("Denied Events", denied(ctx, a.TotalDeniedEvents))
	}
	if a.ClickOpsCount > 0 {
		kv.Add("ClickOps", clickops(ctx, a.ClickOpsCount))
	}
	b.WriteString(ctx.RenderKV(kv, 0))
	b.WriteString(TopEvents(ctx, a.TopEventNames))
	b.WriteString(DeniedEvents(ctx, a.TotalDeniedEvents, a.TopDeniedEventNames))
	b.WriteString(relatedSessions(ctx, detail.Related.Sessions))
	b.WriteString(relatedPeople(ctx, detail.Related.People))
	b.WriteString(relatedRoles(ctx, detail.Related.Roles))
	b.WriteString(relatedServices(ctx, detail.Related.Services))
	b.WriteString(relatedResources(ctx, detail.Related.Resources))
	b.WriteString(nounNavigation(ctx, accountDetailCommands(detail)))
	return b.String()
}

// RoleDetail renders role activity, denied context, and exact relationships.
func RoleDetail(ctx render.Context, detail *models.RoleDetail) string {
	r := &detail.Role
	var b strings.Builder
	b.WriteString(ctx.Title(ctx.Style(render.Ident, r.Name)))
	kv := render.NewKV().
		Add("Role ID", ctx.Style(render.Ident, r.RoleID())).
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
	b.WriteString(TopEvents(ctx, r.TopEventNames))
	b.WriteString(DeniedEvents(ctx, r.TotalDeniedEvents, r.TopDeniedEventNames))
	b.WriteString(countTable(ctx, "Services", "EVENT SOURCE", r.ServicesCount))
	b.WriteString(RoleResourceActivity(ctx, r.ResourceAccesses))
	b.WriteString(RoleDeniedActivity(ctx, r.DeniedResourceAccesses, r.DeniedEventAccesses))
	b.WriteString(relatedSessions(ctx, detail.Related.Sessions))
	b.WriteString(relatedPeople(ctx, detail.Related.People))
	b.WriteString(nounNavigation(ctx, roleDetailCommands(detail)))
	return b.String()
}

// ServiceDetail renders the services detail view.
func ServiceDetail(ctx render.Context, detail *models.ServiceDetail) string {
	svc := &detail.Service
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

	b.WriteString(TopEvents(ctx, svc.TopEventNames))
	b.WriteString(DeniedEvents(ctx, svc.TotalDeniedEvents, svc.TopDeniedEventNames))
	b.WriteString(relatedRoles(ctx, detail.Related.Roles))
	b.WriteString(relatedResources(ctx, detail.Related.Resources))
	b.WriteString(relatedAccounts(ctx, detail.Related.Accounts))
	b.WriteString(relatedPeople(ctx, detail.Related.People))
	b.WriteString(relatedSessions(ctx, detail.Related.Sessions))
	b.WriteString(nounNavigation(ctx, serviceDetailCommands(detail)))
	return b.String()
}
