package view

import (
	"fmt"
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// PersonDetail renders identity facts, activity, relationships, and
// copy-pasteable commands for a person.
func PersonDetail(ctx render.Context, detail *models.PersonDetail) string {
	person := &detail.Person
	var b strings.Builder
	b.WriteString(ctx.Title(person.DisplayLabel()))

	kv := render.NewKV().
		Add("PID", ident(ctx, person.PID())).
		Add("Person Key", ident(ctx, person.PersonKey)).
		Add("Resolution Tier", personTierLabel(person.Tier))
	if person.Email != "" {
		kv.Add("Primary Email", ident(ctx, person.Email))
	}
	if len(person.EmailsSeen) > 0 {
		aliases := append([]string(nil), person.EmailsSeen...)
		sort.Strings(aliases)
		kv.Add("Email Aliases", strings.Join(aliases, ", "))
	}
	kv.Add("First Seen", ctx.Style(render.Time, person.FirstSeen)).
		Add("Last Seen", ctx.Style(render.Time, person.LastSeen)).
		Add("Events", count(ctx, person.EventsCount)).
		Add("Sessions", count(ctx, person.SessionsCount)).
		Add("Accounts", count(ctx, person.AccountsCount)).
		Add("Roles", count(ctx, person.RolesCount)).
		Add("Services", count(ctx, person.ServicesCount)).
		Add("Resources", count(ctx, person.ResourcesCount))
	if person.DeniedEventCount > 0 {
		kv.Add("Denied Events", denied(ctx, person.DeniedEventCount))
	}
	b.WriteString(ctx.RenderKV(kv, 0))

	b.WriteString(DeniedEvents(ctx, person.DeniedEventCount, person.TopDeniedEventNames))
	b.WriteString(relatedSessions(ctx, detail.Related.Sessions))
	b.WriteString(relatedAccounts(ctx, detail.Related.Accounts))
	b.WriteString(relatedRoles(ctx, detail.Related.Roles))
	b.WriteString(relatedServices(ctx, detail.Related.Services))
	b.WriteString(relatedResources(ctx, detail.Related.Resources))
	b.WriteString(nounNavigation(ctx, personDetailCommands(detail)))
	return b.String()
}

// ResourceDetail renders resource facts, activity, relationships, ClickOps
// history, and copy-pasteable commands.
func ResourceDetail(ctx render.Context, detail *models.ResourceDetail) string {
	resource := &detail.Resource
	title := resource.Name
	if title == "" {
		title = resource.Identifier
	}

	var b strings.Builder
	b.WriteString(ctx.Title(title))
	kv := render.NewKV().
		Add("RID", ident(ctx, resource.RID())).
		Add("Identifier", ident(ctx, resource.Identifier))
	if resource.ARN != "" {
		kv.Add("ARN", ident(ctx, resource.ARN))
	}
	if resource.Type != "" {
		kv.Add("Type", resource.Type)
	}
	if resource.Name != "" && resource.Name != resource.Identifier {
		kv.Add("Name", resource.Name)
	}
	kv.Add("Account", ident(ctx, resource.AccountID)).
		Add("First Seen", ctx.Style(render.Time, resource.FirstSeen)).
		Add("Last Seen", ctx.Style(render.Time, resource.LastSeen)).
		Add("Events", count(ctx, resource.TotalEvents)).
		Add("Roles", count(ctx, resource.RolesCount)).
		Add("People", count(ctx, resource.PeopleCount)).
		Add("Sessions", count(ctx, resource.SessionsCount))
	if resource.TotalDeniedEvents > 0 {
		kv.Add("Denied Events", denied(ctx, resource.TotalDeniedEvents))
	}
	if resource.ClickOpsCount > 0 {
		kv.Add("ClickOps", clickops(ctx, resource.ClickOpsCount))
	}
	b.WriteString(ctx.RenderKV(kv, 0))

	b.WriteString(TopEvents(ctx, resource.TopEventNames))
	b.WriteString(DeniedEvents(ctx, resource.TotalDeniedEvents, resource.TopDeniedEventNames))
	b.WriteString(relatedRoles(ctx, detail.Related.Roles))
	b.WriteString(relatedServices(ctx, detail.Related.Services))
	b.WriteString(relatedPeople(ctx, detail.Related.People))
	b.WriteString(relatedSessions(ctx, detail.Related.Sessions))
	b.WriteString(resourceClickOps(ctx, detail))
	b.WriteString(nounNavigation(ctx, resourceDetailCommands(detail)))
	return b.String()
}

func personTierLabel(tier int) string {
	switch tier {
	case 1:
		return "Identity Center"
	case 2:
		return "Credential link"
	case 3:
		return "Email session"
	case 4:
		return "IAM user"
	case 5:
		return "Root"
	default:
		return "Unknown"
	}
}

func relatedSessions(ctx render.Context, sessions []models.RelatedSession) string {
	if len(sessions) == 0 {
		return ""
	}
	base := make([]models.Session, len(sessions))
	for i := range sessions {
		base[i] = sessions[i].Session
	}
	sidWidth := SidDisplayWidth(base)
	t := render.NewTable(
		render.Column{Header: "SID", Align: render.AlignLeft},
		render.Column{Header: "ROLE", Align: render.AlignLeft},
		render.Column{Header: "ACCOUNT", Align: render.AlignLeft},
		render.Column{Header: "TYPE", Align: render.AlignLeft},
		render.Column{Header: "EVENTS", Align: render.AlignRight},
		render.Column{Header: "TIME", Align: render.AlignLeft},
	)
	for i := range sessions {
		session := &sessions[i].Session
		sid := ShortSid(session, sidWidth)
		if sid == "-" {
			sid = shortID(models.SidForRef(session.Ref()), sidWidth)
		}
		role := session.RoleName
		if role == "" {
			role = session.RoleARN
		}
		t.Row(
			ident(ctx, sid),
			ident(ctx, ShortRoleName(role)),
			session.AccountID,
			session.DetectSessionType(),
			count(ctx, session.EventsCount),
			ctx.Style(render.Time, session.StartTime),
		)
	}
	return ctx.Section(render.Heading("Recent Sessions", len(sessions)), ctx.RenderTable(t, render.BodyIndent))
}

func relatedAccounts(ctx render.Context, accounts []models.RelatedAccount) string {
	if len(accounts) == 0 {
		return ""
	}
	t := render.NewTable(
		render.Column{Header: "ACCOUNT ID", Align: render.AlignLeft},
		render.Column{Header: "NAME", Align: render.AlignLeft},
		render.Column{Header: "LAST RELATED", Align: render.AlignLeft},
	)
	for i := range accounts {
		t.Row(
			ident(ctx, accounts[i].AccountID),
			accounts[i].AccountName,
			ctx.Style(render.Time, accounts[i].RelationshipLastSeen),
		)
	}
	return ctx.Section(render.Heading("Accounts", len(accounts)), ctx.RenderTable(t, render.BodyIndent))
}

func relatedRoles(ctx render.Context, roles []models.RelatedRole) string {
	if len(roles) == 0 {
		return ""
	}
	t := render.NewTable(
		render.Column{Header: "ROLE ARN", Align: render.AlignLeft},
		render.Column{Header: "LAST RELATED", Align: render.AlignLeft},
	)
	for i := range roles {
		t.Row(
			ident(ctx, roles[i].ARN),
			ctx.Style(render.Time, roles[i].RelationshipLastSeen),
		)
	}
	return ctx.Section(render.Heading("Roles", len(roles)), ctx.RenderTable(t, render.BodyIndent))
}

func relatedServices(ctx render.Context, services []models.RelatedService) string {
	if len(services) == 0 {
		return ""
	}
	t := render.NewTable(
		render.Column{Header: "EVENT SOURCE", Align: render.AlignLeft},
		render.Column{Header: "LAST RELATED", Align: render.AlignLeft},
	)
	for i := range services {
		t.Row(
			ident(ctx, services[i].EventSource),
			ctx.Style(render.Time, services[i].RelationshipLastSeen),
		)
	}
	return ctx.Section(render.Heading("Services", len(services)), ctx.RenderTable(t, render.BodyIndent))
}

func relatedResources(ctx render.Context, resources []models.RelatedResource) string {
	if len(resources) == 0 {
		return ""
	}
	base := make([]models.Resource, len(resources))
	for i := range resources {
		base[i] = resources[i].Resource
	}
	ridWidth := ResourceIDDisplayWidth(base)
	t := render.NewTable(
		render.Column{Header: "RID", Align: render.AlignLeft},
		render.Column{Header: "RESOURCE", Align: render.AlignLeft},
		render.Column{Header: "ACCOUNT", Align: render.AlignLeft},
		render.Column{Header: "LAST RELATED", Align: render.AlignLeft},
	)
	for i := range resources {
		resource := &resources[i].Resource
		t.Row(
			ident(ctx, ShortResourceID(resource, ridWidth)),
			ident(ctx, resource.Identifier),
			resource.AccountID,
			ctx.Style(render.Time, resources[i].RelationshipLastSeen),
		)
	}
	return ctx.Section(render.Heading("Resources", len(resources)), ctx.RenderTable(t, render.BodyIndent))
}

func relatedPeople(ctx render.Context, people []models.RelatedPerson) string {
	if len(people) == 0 {
		return ""
	}
	base := make([]models.Person, len(people))
	for i := range people {
		base[i] = people[i].Person
	}
	pidWidth := PersonIDDisplayWidth(base)
	t := render.NewTable(
		render.Column{Header: "PID", Align: render.AlignLeft},
		render.Column{Header: "PERSON", Align: render.AlignLeft},
		render.Column{Header: "LAST RELATED", Align: render.AlignLeft},
	)
	for i := range people {
		person := &people[i].Person
		t.Row(
			ident(ctx, ShortPersonID(person, pidWidth)),
			person.DisplayLabel(),
			ctx.Style(render.Time, people[i].RelationshipLastSeen),
		)
	}
	return ctx.Section(render.Heading("People", len(people)), ctx.RenderTable(t, render.BodyIndent))
}

func resourceClickOps(ctx render.Context, detail *models.ResourceDetail) string {
	if len(detail.ClickOpsAccesses) == 0 {
		return ""
	}
	labels := make(map[string]string, len(detail.Related.People))
	for i := range detail.Related.People {
		labels[detail.Related.People[i].PersonKey] = detail.Related.People[i].DisplayLabel()
	}

	accesses := append([]models.ClickOpsAccess(nil), detail.ClickOpsAccesses...)
	sort.Slice(accesses, func(i, j int) bool {
		if accesses[i].AccessTime != accesses[j].AccessTime {
			return accesses[i].AccessTime > accesses[j].AccessTime
		}
		if accesses[i].EventName != accesses[j].EventName {
			return accesses[i].EventName < accesses[j].EventName
		}
		return accesses[i].PersonKey < accesses[j].PersonKey
	})

	t := render.NewTable(
		render.Column{Header: "ACTOR", Align: render.AlignLeft},
		render.Column{Header: "EVENT", Align: render.AlignLeft},
		render.Column{Header: "COUNT", Align: render.AlignRight},
		render.Column{Header: "TIME", Align: render.AlignLeft},
		render.Column{Header: "SID", Align: render.AlignLeft},
	)
	for _, access := range accesses {
		actor := labels[access.PersonKey]
		if actor == "" {
			actor = ShortPersonKey(access.PersonKey)
		}
		sid := "-"
		if access.SessionRef != "" {
			sid = shortID(models.SidForRef(access.SessionRef), sidDisplayMin)
		}
		t.Row(
			actor,
			ident(ctx, access.EventName),
			clickops(ctx, access.EventCount),
			ctx.Style(render.Time, access.AccessTime),
			ident(ctx, sid),
		)
	}
	return ctx.Section(render.Heading("Console Operations", len(accesses)), ctx.RenderTable(t, render.BodyIndent))
}

func personDetailCommands(detail *models.PersonDetail) []string {
	var commands []string
	for i := range detail.Related.Sessions {
		commands = append(commands, "trailtool sessions detail "+sessionSelector(&detail.Related.Sessions[i].Session))
	}
	for i := range detail.Related.Accounts {
		commands = append(commands, "trailtool accounts detail "+detail.Related.Accounts[i].AccountID)
	}
	for i := range detail.Related.Roles {
		commands = append(commands, "trailtool roles detail "+detail.Related.Roles[i].ARN)
	}
	for i := range detail.Related.Services {
		commands = append(commands, "trailtool services detail "+detail.Related.Services[i].EventSource)
	}
	for i := range detail.Related.Resources {
		commands = append(commands, "trailtool resources detail "+detail.Related.Resources[i].RID())
	}
	return commands
}

func resourceDetailCommands(detail *models.ResourceDetail) []string {
	commands := []string{"trailtool accounts detail " + detail.AccountID}
	for i := range detail.Related.Roles {
		commands = append(commands, "trailtool roles detail "+detail.Related.Roles[i].ARN)
	}
	for i := range detail.Related.Services {
		commands = append(commands, "trailtool services detail "+detail.Related.Services[i].EventSource)
	}
	for i := range detail.Related.People {
		commands = append(commands, "trailtool people detail "+detail.Related.People[i].PID())
	}
	for i := range detail.Related.Sessions {
		commands = append(commands, "trailtool sessions detail "+sessionSelector(&detail.Related.Sessions[i].Session))
	}
	for _, access := range detail.ClickOpsAccesses {
		if access.SessionRef != "" {
			commands = append(commands, "trailtool sessions detail "+models.SidForRef(access.SessionRef))
		}
	}
	return commands
}

func sessionSelector(session *models.Session) string {
	if session.Sid != "" {
		return session.Sid
	}
	return models.SidForRef(session.Ref())
}

func nounNavigation(ctx render.Context, commands []string) string {
	if len(commands) == 0 {
		return ""
	}
	seen := make(map[string]bool, len(commands))
	var b strings.Builder
	for _, command := range commands {
		if command == "" || seen[command] {
			continue
		}
		seen[command] = true
		fmt.Fprintf(&b, "  %s\n", ctx.Style(render.Nav, ctx.Symbol(render.SymNav)+" "+command))
	}
	if b.Len() == 0 {
		return ""
	}
	return ctx.Section(render.Heading("Explore", -1), b.String())
}
