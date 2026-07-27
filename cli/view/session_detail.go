package view

import (
	"fmt"
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// SessionOriginReference is the resolved session that created or authorized
// the current session. The command layer owns the store lookup; this view only
// formats the result.
type SessionOriginReference struct {
	Ref         string
	PersonLabel string
	Session     *models.Session
}

// SessionLineageRow is one outbound session relationship. Compact session
// identity, including the top client, is rendered consistently with noun detail
// Recent Sessions tables.
type SessionLineageRow struct {
	Relation    string
	Ref         string
	PersonLabel string
	Role        string
	Session     *models.Session
}

// SessionOverview renders the session identity and high-signal scalar facts.
// Diagnostic storage keys are available only in verbose output.
func SessionOverview(ctx render.Context, sess *models.Session, personLabel, timeLine string, verbose bool) string {
	var b strings.Builder

	sid := sess.Sid
	if sid == "" {
		sid = models.SidForRef(sess.Ref())
	}
	b.WriteString(ctx.Title("Session " + sid))

	role := sess.RoleName
	if role == "" {
		role = sess.RoleARN
	}
	if sess.RoleARN != "" && sess.RoleARN != role {
		role = ctx.Style(render.Ident, role) + "  " + ctx.Style(render.Muted, "("+sess.RoleARN+")")
	} else {
		role = ctx.Style(render.Ident, role)
	}
	kv := render.NewKV().
		Add("Person", personLabel).
		Add("Role", role).
		Add("Account", sess.AccountID).
		Add("Type", sess.DetectSessionType()).
		Add("Time", ctx.Style(render.Time, timeLine)).
		Add("Activity", activityFact(ctx, sess))
	if verbose {
		kv.Add("Internal SK", ctx.Style(render.Muted, sess.SK))
		if sess.Anchor != "" {
			kv.Add("Anchor", ctx.Style(render.Muted, sess.Anchor))
		}
	}
	if len(sess.SourceIPs) > 0 {
		sourceIPs := append([]string(nil), sess.SourceIPs...)
		sort.Strings(sourceIPs)
		kv.Add("Source IPs", strings.Join(sourceIPs, ", "))
	}
	if sess.DeniedEventCount > 0 {
		kv.Add("Denied Events", denied(ctx, sess.DeniedEventCount))
	}
	if sess.ClickOpsEventCount > 0 {
		kv.Add("ClickOps", clickops(ctx, sess.ClickOpsEventCount))
	}
	if sess.ServiceDrivenEventCount > 0 {
		kv.Add("Service-driven", n(sess.ServiceDrivenEventCount)+" (AWS services calling with these credentials)")
	}
	b.WriteString(ctx.RenderKV(kv, 0))
	return b.String()
}

func activityFact(ctx render.Context, sess *models.Session) string {
	events := ctx.Style(render.Count, quantity(sess.EventsCount, "event"))
	return fmt.Sprintf("%s across %s, %s",
		events,
		quantity(sess.ServicesCount, "service"),
		quantity(sess.ResourcesCount, "resource"),
	)
}

func quantity(value int, singular string) string {
	label := singular
	if value != 1 {
		label += "s"
	}
	return n(value) + " " + label
}

// SessionOrigin renders how the credentials were created or authorized. It
// collects role-session, tag, policy, MCP, login, and chain metadata into one
// aligned section instead of emitting loose facts throughout the page.
func SessionOrigin(
	ctx render.Context,
	sess *models.Session,
	parent SessionOriginReference,
	verbose bool,
) string {
	method, relation := sessionOriginMethod(sess)
	hasOrigin := method != "" ||
		sess.RoleSessionName != "" ||
		len(sess.SessionTags) > 0 ||
		sessionHasPolicy(sess) ||
		parent.Ref != "" ||
		sess.MCPResource != "" ||
		(verbose && sess.SignInSessionArn != "")
	if !hasOrigin {
		return ""
	}

	kv := render.NewKV()
	if method != "" {
		kv.Add("Method", method)
	}
	if sess.MCPResource != "" {
		kv.Add("Resource", ctx.Style(render.Ident, sess.MCPResource))
	}
	if sess.RoleSessionName != "" {
		kv.Add("Role session", ctx.Style(render.Ident, sess.RoleSessionName))
	}
	if tags := sessionTagsInline(sess.SessionTags); tags != "" {
		kv.Add("Tags", tags)
	}
	kv.Add("Session policy", sessionPolicySummary(ctx, sess))
	if verbose && sess.SignInSessionArn != "" {
		kv.Add("Sign-in session", ctx.Style(render.Muted, sess.SignInSessionArn))
	}
	if parent.Ref != "" {
		kv.Add(relation, sessionReferenceSummary(ctx, parent))
	}
	return ctx.Section(render.Heading("Origin", -1), ctx.RenderKV(kv, render.BodyIndent))
}

func sessionOriginMethod(sess *models.Session) (method, relation string) {
	switch {
	case sess.AgentAuthorizedBySession != "" || sess.MCPResource != "":
		return "AWS MCP Server OAuth", "Authorized by"
	case sess.LoginGrantedBySession != "":
		return "aws login", "Granted by"
	case sess.AssumedFromSession != "":
		return "AssumeRole", "Assumed by"
	default:
		return "", "Created by"
	}
}

func sessionTagsInline(tags map[string]string) string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, k := range keys {
		values = append(values, k+"="+tags[k])
	}
	return strings.Join(values, ", ")
}

func sessionReferenceSummary(ctx render.Context, reference SessionOriginReference) string {
	parts := []string{ident(ctx, shortID(models.SidForRef(reference.Ref), sidDisplayMin))}
	if reference.PersonLabel != "" {
		parts = append(parts, reference.PersonLabel)
	}
	if reference.Session != nil {
		role := reference.Session.RoleName
		if role == "" {
			role = reference.Session.RoleARN
		}
		if role != "" {
			parts = append(parts, ident(ctx, ShortRoleName(role)))
		}
		if reference.Session.StartTime != "" {
			parts = append(parts, ctx.Style(render.Time, ctx.Relative(reference.Session.StartTime)))
		}
	}
	return strings.Join(parts, " · ")
}

// SessionLineage renders sessions this session assumed or authorized.
func SessionLineage(ctx render.Context, rows []SessionLineageRow, omitted int) string {
	if len(rows) == 0 && omitted == 0 {
		return ""
	}
	showClient := ctx.Width >= 80
	columns := []render.Column{
		{Header: "RELATION", Align: render.AlignLeft},
		{Header: "SID", Align: render.AlignLeft},
		{Header: "PERSON", Align: render.AlignLeft},
		{Header: "ROLE", Align: render.AlignLeft},
	}
	if showClient {
		columns = append(columns, render.Column{Header: "CLIENT", Align: render.AlignLeft})
	}
	columns = append(columns,
		render.Column{Header: "EVENTS", Align: render.AlignRight},
		render.Column{Header: "TIME", Align: render.AlignLeft},
	)

	table := render.NewTable(columns...)
	for _, row := range rows {
		sid := "-"
		person := row.PersonLabel
		role := row.Role
		client := "-"
		events := "-"
		when := "-"
		if row.Ref != "" {
			sid = shortID(models.SidForRef(row.Ref), sidDisplayMin)
		}
		if row.Session != nil {
			if row.Session.Sid != "" {
				sid = shortID(row.Session.Sid, sidDisplayMin)
			}
			if role == "" {
				role = row.Session.RoleName
				if role == "" {
					role = row.Session.RoleARN
				}
			}
			client = topClientSummary(row.Session.Clients)
			events = count(ctx, row.Session.EventsCount)
			if row.Session.StartTime != "" {
				when = ctx.Relative(row.Session.StartTime)
			}
		}
		cells := []string{
			row.Relation,
			ident(ctx, sid),
			optional(ctx, person),
			optional(ctx, ctx.Truncate(ShortRoleName(role), 24)),
		}
		if showClient {
			cells = append(cells, optional(ctx, ctx.Truncate(client, 16)))
		}
		cells = append(cells, events, ctx.Style(render.Time, when))
		table.Row(cells...)
	}

	body := ctx.RenderTable(table, render.BodyIndent)
	if omitted > 0 {
		body += "  " + ctx.Style(render.Muted, fmt.Sprintf("+%d more (use --all to show every row)", omitted)) + "\n"
	}
	return ctx.Section(render.Heading("Lineage", len(rows)+omitted), body)
}

// DeniedEvents renders the Denied Events section (§5): the API calls this
// session made that AWS rejected with an explicit deny or AccessDenied. When a
// per-call breakdown is available (counts), it renders a count-descending table
// like Top Events, with the counts Denied-accented and a leading ⊘/(denied)
// accent on the heading. When only the total is known (older records with no
// breakdown), it falls back to a one-line count so no signal is lost. Returns ""
// when the session had no denials.
func DeniedEvents(ctx render.Context, total int, counts map[string]int) string {
	if total <= 0 && len(counts) == 0 {
		return ""
	}
	heading := ctx.Symbol(render.SymDenied) + " Denied Events"

	// No breakdown: keep the explanatory one-line count.
	if len(counts) == 0 {
		return "\n" + ctx.Style(render.Denied, heading+": "+n(total)) +
			ctx.Style(render.Muted, "  (calls AWS rejected with AccessDenied)") + "\n"
	}

	rows := sortByCountDesc(counts)
	t := render.NewTable(
		render.Column{Header: "EVENT", Align: render.AlignLeft},
		render.Column{Header: "DENIED", Align: render.AlignRight},
	)
	for _, r := range rows {
		t.Row(ctx.Style(render.Ident, r.name), ctx.Style(render.Denied, n(r.count)))
	}
	head := ctx.Style(render.Denied, heading) + " " + ctx.Style(render.Muted, "(calls AWS rejected):")
	return ctx.Section(head, ctx.RenderTable(t, render.BodyIndent))
}

// TopEvents renders the Top Events section as a count-descending table (fixes
// today's alphabetical sort, §5). Ties break by event name for stability. "" when
// empty.
func TopEvents(ctx render.Context, counts map[string]int) string {
	return countTable(ctx, "Top Events", "EVENT", counts)
}

// countRow is one name→count pair for a count-descending table.
type countRow struct {
	name  string
	count int
}

// sortByCountDesc flattens a name→count map into rows sorted count-descending,
// ties broken by name for stable output.
func sortByCountDesc(counts map[string]int) []countRow {
	rows := make([]countRow, 0, len(counts))
	for k, v := range counts {
		rows = append(rows, countRow{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})
	return rows
}

// countTable renders a name→count map as a count-descending two-column table in
// a titled section. Ties break by name. Returns "" when the map is empty.
func countTable(ctx render.Context, heading, nameHeader string, counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	rows := sortByCountDesc(counts)
	t := render.NewTable(
		render.Column{Header: nameHeader, Align: render.AlignLeft},
		render.Column{Header: "COUNT", Align: render.AlignRight},
	)
	for _, r := range rows {
		t.Row(ctx.Style(render.Ident, r.name), ctx.Style(render.Count, n(r.count)))
	}
	return ctx.Section(render.Heading(heading, len(rows)), ctx.RenderTable(t, render.BodyIndent))
}

// SessionPolicy renders the Session Policy section: pretty-printed JSON indented
// two spaces (§5). Returns "" when the session carries no policy. Invalid JSON
// falls back to the raw string, matching shipped behavior.
func SessionPolicy(ctx render.Context, policyJSON string) string {
	if policyJSON == "" {
		return ""
	}
	pretty, err := PrettyJSON(policyJSON)
	if err != nil {
		pretty = policyJSON
	}
	var b strings.Builder
	for _, line := range strings.Split(pretty, "\n") {
		b.WriteString("  " + line + "\n")
	}
	return ctx.Section(render.Heading("Session Policy", -1), b.String())
}
