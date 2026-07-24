package view

import (
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// Session-detail sections (§5), each a pure render of already-fetched models.
// The command layer orchestrates the fixed section order and interleaves the
// store-backed lineage navigation (printRefNav), which cannot live here because
// it touches the store. Order and semantics match the shipped detail view; only
// styling and the Top-Events sort change.

// SessionTitleKV renders the Title (user) and the KV key-facts block (§5): role,
// account, type, session id, time, events. timeLine is the already-formatted
// interval + relative suffix built by the command (which owns "now"). Kept
// separate from lineage so the command can print store-backed sections in the
// fixed order between the header and the policy.
func SessionTitleKV(ctx render.Context, sess *models.Session, personLabel, timeLine string) string {
	var b strings.Builder
	b.WriteString(ctx.Title(personLabel + "  " + ctx.Style(render.Muted, "("+sess.PersonKey+")")))

	kv := render.NewKV().
		Add("Role", ctx.Style(render.Ident, sess.RoleName)+"  "+ctx.Style(render.Muted, "("+sess.RoleARN+")")).
		Add("Account", sess.AccountID).
		Add("Type", sess.DetectSessionType()).
		Add("Session", ctx.Style(render.Ident, sess.SK)).
		Add("Time", ctx.Style(render.Time, timeLine)).
		Add("Events", eventsFact(ctx, sess))
	if sess.ServiceDrivenEventCount > 0 {
		kv.Add("Service-driven", n(sess.ServiceDrivenEventCount)+" (AWS services calling with these credentials)")
	}
	b.WriteString(ctx.RenderKV(kv, 0))
	return b.String()
}

// eventsFact renders the "Events" fact: "N across M services".
func eventsFact(ctx render.Context, sess *models.Session) string {
	return ctx.Style(render.Count, n(sess.EventsCount)) + " across " + n(sess.ServicesCount) + " services"
}

// SessionTags renders the Session Tags section (sorted by key), or "" when none.
func SessionTags(ctx render.Context, tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString("  " + k + ": " + tags[k] + "\n")
	}
	return ctx.Section(render.Heading("Session Tags", -1), b.String())
}

// DeniedEvents renders the one-line Denied Events count when nonzero, "" else.
// It is Denied-styled and carries the word, so it reads without color.
func DeniedEvents(ctx render.Context, count int) string {
	if count <= 0 {
		return ""
	}
	return "\n" + ctx.Style(render.Denied, ctx.Symbol(render.SymDenied)+" Denied Events: "+n(count)) + "\n"
}

// TopEvents renders the Top Events section as a count-descending table (fixes
// today's alphabetical sort, §5). Ties break by event name for stability. "" when
// empty.
func TopEvents(ctx render.Context, counts map[string]int) string {
	return countTable(ctx, "Top Events", "EVENT", counts)
}

// ResourcesAccessed renders the Resources Accessed section, count-descending.
func ResourcesAccessed(ctx render.Context, counts map[string]int) string {
	return countTable(ctx, "Resources Accessed", "RESOURCE", counts)
}

// countTable renders a name→count map as a count-descending two-column table in
// a titled section. Ties break by name. Returns "" when the map is empty.
func countTable(ctx render.Context, heading, nameHeader string, counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	type kv struct {
		name  string
		count int
	}
	rows := make([]kv, 0, len(counts))
	for k, v := range counts {
		rows = append(rows, kv{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})
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
