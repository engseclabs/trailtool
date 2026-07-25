package view

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

type detailAccessRow struct {
	service      string
	event        string
	resource     string
	accountID    string
	count        int
	policyARN    string
	policyType   string
	errorMessage string
}

// SessionResourceActivity renders successful event-to-resource activity.
func SessionResourceActivity(ctx render.Context, accesses []models.ResourceAccess) string {
	rows := make([]detailAccessRow, 0, len(accesses))
	for _, access := range accesses {
		rows = append(rows, detailAccessRow{
			service:   access.Service,
			event:     access.EventName,
			resource:  access.Resource,
			accountID: access.ResourceAccountID,
			count:     access.Count,
		})
	}
	return detailAccessTable(ctx, "Event to Resource Activity", rows, false)
}

// RoleResourceActivity renders successful event-to-resource activity for a
// role aggregate.
func RoleResourceActivity(ctx render.Context, accesses []models.ResourceAccessItem) string {
	rows := make([]detailAccessRow, 0, len(accesses))
	for _, access := range accesses {
		rows = append(rows, detailAccessRow{
			service:   access.Service,
			event:     access.EventName,
			resource:  access.Resource,
			accountID: access.ResourceAccountID,
			count:     access.Count,
		})
	}
	return detailAccessTable(ctx, "Event to Resource Activity", rows, false)
}

// SessionDeniedActivity renders resource-backed and resource-less denied calls
// with policy and bounded error context.
func SessionDeniedActivity(
	ctx render.Context,
	resourceAccesses []models.ResourceAccess,
	eventAccesses []models.EventAccess,
) string {
	rows := make([]detailAccessRow, 0, len(resourceAccesses)+len(eventAccesses))
	for _, access := range resourceAccesses {
		rows = append(rows, detailAccessRow{
			service: access.Service, event: access.EventName, resource: access.Resource,
			accountID: access.ResourceAccountID, count: access.Count,
			policyARN: access.PolicyARN, policyType: access.PolicyType, errorMessage: access.ErrorMessage,
		})
	}
	for _, access := range eventAccesses {
		rows = append(rows, detailAccessRow{
			service: access.Service, event: access.EventName, resource: "-",
			count: access.Count, policyARN: access.PolicyARN,
			policyType: access.PolicyType, errorMessage: access.ErrorMessage,
		})
	}
	return detailAccessTable(ctx, "Denied Activity Details", rows, true)
}

// RoleDeniedActivity renders denied role activity with the same context as a
// session detail.
func RoleDeniedActivity(
	ctx render.Context,
	resourceAccesses []models.ResourceAccessItem,
	eventAccesses []models.EventAccessItem,
) string {
	rows := make([]detailAccessRow, 0, len(resourceAccesses)+len(eventAccesses))
	for _, access := range resourceAccesses {
		rows = append(rows, detailAccessRow{
			service: access.Service, event: access.EventName, resource: access.Resource,
			accountID: access.ResourceAccountID, count: access.Count,
			policyARN: access.PolicyARN, policyType: access.PolicyType, errorMessage: access.ErrorMessage,
		})
	}
	for _, access := range eventAccesses {
		rows = append(rows, detailAccessRow{
			service: access.Service, event: access.EventName, resource: "-",
			count: access.Count, policyARN: access.PolicyARN,
			policyType: access.PolicyType, errorMessage: access.ErrorMessage,
		})
	}
	return detailAccessTable(ctx, "Denied Activity Details", rows, true)
}

func detailAccessTable(ctx render.Context, heading string, rows []detailAccessRow, deniedRows bool) string {
	if len(rows) == 0 {
		return ""
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		if rows[i].service != rows[j].service {
			return rows[i].service < rows[j].service
		}
		if rows[i].event != rows[j].event {
			return rows[i].event < rows[j].event
		}
		if rows[i].accountID != rows[j].accountID {
			return rows[i].accountID < rows[j].accountID
		}
		return rows[i].resource < rows[j].resource
	})

	columns := []render.Column{
		{Header: "SERVICE", Align: render.AlignLeft},
		{Header: "EVENT", Align: render.AlignLeft},
		{Header: "RESOURCE", Align: render.AlignLeft},
		{Header: "ACCOUNT", Align: render.AlignLeft},
	}
	countHeader := "COUNT"
	if deniedRows {
		countHeader = "DENIED"
	}
	columns = append(columns, render.Column{Header: countHeader, Align: render.AlignRight})
	if deniedRows {
		columns = append(columns,
			render.Column{Header: "POLICY ARN", Align: render.AlignLeft},
			render.Column{Header: "POLICY TYPE", Align: render.AlignLeft},
			render.Column{Header: "ERROR", Align: render.AlignLeft},
		)
	}

	table := render.NewTable(columns...)
	for _, row := range rows {
		accountID := row.accountID
		if accountID == "" {
			accountID = "-"
		}
		cells := []string{
			ident(ctx, row.service),
			ident(ctx, row.event),
			ident(ctx, row.resource),
			accountID,
		}
		if deniedRows {
			cells = append(cells, denied(ctx, row.count))
			cells = append(cells,
				row.policyARN,
				row.policyType,
				boundedError(row.errorMessage),
			)
		} else {
			cells = append(cells, count(ctx, row.count))
		}
		table.Row(cells...)
	}

	if deniedRows {
		heading = ctx.Symbol(render.SymDenied) + " " + heading
	}
	return ctx.Section(render.Heading(heading, len(rows)), ctx.RenderTable(table, render.BodyIndent))
}

func boundedError(message string) string {
	const maxRunes = 96
	message = strings.Join(strings.Fields(message), " ")
	if utf8.RuneCountInString(message) <= maxRunes {
		return message
	}
	runes := []rune(message)
	return string(runes[:maxRunes-1]) + "…"
}

// SessionClickOps renders the console event breakdown.
func SessionClickOps(ctx render.Context, total int, counts map[string]int) string {
	if total == 0 && len(counts) == 0 {
		return ""
	}
	if len(counts) == 0 {
		return ctx.Section(
			render.Heading("ClickOps Events", total),
			"  "+ctx.Style(render.Warn, n(total))+"\n",
		)
	}

	rows := sortByCountDesc(counts)
	table := render.NewTable(
		render.Column{Header: "EVENT", Align: render.AlignLeft},
		render.Column{Header: "CLICKOPS", Align: render.AlignRight},
	)
	for _, row := range rows {
		table.Row(ident(ctx, row.name), clickops(ctx, row.count))
	}
	return ctx.Section(render.Heading("ClickOps Events", total), ctx.RenderTable(table, render.BodyIndent))
}

// SessionSummary renders a cached summary and its provenance.
func SessionSummary(ctx render.Context, session *models.Session) string {
	if session.Summary == "" {
		return ""
	}
	var body strings.Builder
	for _, line := range strings.Split(session.Summary, "\n") {
		body.WriteString("  " + line + "\n")
	}
	if session.SummaryModel != "" || session.SummaryGeneratedAt != "" {
		body.WriteByte('\n')
		kv := render.NewKV()
		if session.SummaryModel != "" {
			kv.Add("Model", session.SummaryModel)
		}
		if session.SummaryGeneratedAt != "" {
			kv.Add("Generated", ctx.Style(render.Time, session.SummaryGeneratedAt))
		}
		body.WriteString(ctx.RenderKV(kv, render.BodyIndent))
	}
	return ctx.Section(render.Heading("Cached Summary", -1), body.String())
}
