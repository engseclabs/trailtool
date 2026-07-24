package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/session"
	"github.com/engseclabs/trailtool/core/store"
	"github.com/engseclabs/trailtool/internal/render"
)

// Format holds the value of the global --format flag ("text" or "json"). It is
// bound by main.go's persistent flag registration.
var Format = "text"

// ColorMode holds the value of the global --color flag ("auto", "always", or
// "never"). It is bound by main.go's persistent flag registration.
var ColorMode = "auto"

// renderContext resolves the terminal capabilities once per command, per §4.1.
// Views are threaded the returned Context and never re-read the environment.
// An unrecognized --color value falls back to auto (the flag's help lists the
// valid values; Cobra does not enum-validate it).
func renderContext() render.Context {
	mode, _ := render.ParseColorMode(ColorMode)
	return render.Detect(mode, os.Stdout, os.Stderr)
}

// CustomerID identifies the tenant whose data the CLI queries. It defaults to
// "default" and is overridden by TRAILTOOL_CUSTOMER_ID.
var CustomerID = "default"

func init() {
	if id := os.Getenv("TRAILTOOL_CUSTOMER_ID"); id != "" {
		CustomerID = id
	}
}

// personLabels fetches the people table once and returns a resolver mapping
// person keys to their friendliest display label (display name, email, or the
// key itself).
func personLabels(ctx context.Context, s *store.Store) func(string) string {
	labels := map[string]string{}
	if people, err := s.ListPeople(ctx, CustomerID); err == nil {
		for i := range people {
			labels[people[i].PersonKey] = people[i].DisplayLabel()
		}
	}
	return func(key string) string {
		if l, ok := labels[key]; ok && l != "" {
			return l
		}
		return view.ShortPersonKey(key)
	}
}

// printRefNav prints one attribution line (who + when) for a session ref,
// followed by a copy-pasteable detail command when the target is fetchable. The
// heading is word-led (SymSource accent) and the nav line uses SymNav, so the
// relationship reads in mono/ASCII (§4.3, §4.5).
func printRefNav(ctx context.Context, rctx render.Context, s *store.Store, heading, ref string, label func(string) string, now time.Time) {
	who := label(view.RefPersonKey(ref))
	src := rctx.Symbol(render.SymSource)
	target, err := s.GetSessionByRef(ctx, CustomerID, ref)
	if err != nil || target == nil {
		fmt.Fprintf(rctx.Out, "%s %s: %s\n", src, rctx.Style(render.Header, heading), who)
		return
	}
	fmt.Fprintf(rctx.Out, "%s %s: %s at %s\n",
		src, rctx.Style(render.Header, heading), who, rctx.Style(render.Time, render.Timestamp(target.StartTime, now)))
	fmt.Fprintf(rctx.Out, "  %s\n", rctx.Style(render.Nav, rctx.Symbol(render.SymNav)+" trailtool sessions detail --session "+view.SidForRefShort(ref)))
}

// printChildRow renders one child/grant session row in the lineage sections:
// a lineage-accented line (role, event/duration counts, timestamp) plus a
// copy-paste nav line to that session's detail. The already-resolved session and
// its display role are passed in so this stays a pure formatter over a fetched
// model; the caller owns the store lookup.
func printChildRow(rctx render.Context, child *models.Session, displayRole, ref string, now time.Time) {
	lineage := rctx.Symbol(render.SymLineage)
	fmt.Fprintf(rctx.Out, "  %s %s  %s  %s events  %dm  %s\n",
		lineage,
		rctx.Style(render.Ident, displayRole),
		rctx.Style(render.Muted, child.DetectSessionType()),
		rctx.Style(render.Count, fmt.Sprintf("%d", child.EventsCount)),
		child.DurationMinutes,
		rctx.Style(render.Time, render.Timestamp(child.StartTime, now)))
	fmt.Fprintf(rctx.Out, "    %s\n",
		rctx.Style(render.Nav, rctx.Symbol(render.SymNav)+" trailtool sessions detail --session "+view.SidForRefShort(ref)))
}

// resolveSession finds a single session by --session: a sid prefix, or "latest".
// An empty prefix, no match, or an ambiguous prefix each return an actionable
// error.
func resolveSession(ctx context.Context, s *store.Store, sel, user string) (*models.Session, error) {
	if sel == "latest" {
		filter := store.SessionFilter{Days: 90}
		sessions, _, err := session.ListSessions(ctx, s, CustomerID, user, filter)
		if err != nil {
			return nil, err
		}
		if len(sessions) == 0 {
			return nil, fmt.Errorf("no sessions found")
		}
		latest := sessions[len(sessions)-1]
		return &latest, nil
	}

	matches, err := s.FindSessionsBySidPrefix(ctx, CustomerID, sel)
	if err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no session found with id %q (check 'trailtool sessions list')", sel)
	case 1:
		return &matches[0], nil
	default:
		// Ambiguous prefix: show each match with just enough of the sid to
		// distinguish it, plus who/when, and ask the user to lengthen.
		width := view.SidDisplayWidth(matches)
		if width <= len(sel) {
			width = len(sel) + 1
		}
		label := personLabels(ctx, s)
		msg := fmt.Sprintf("%d sessions match id %q — use a longer id:\n", len(matches), sel)
		for i := range matches {
			m := &matches[i]
			msg += fmt.Sprintf("  %s  %s  %s  %s\n",
				view.ShortSid(m, width), m.StartTime, label(m.PersonKey), m.RoleName)
		}
		return nil, fmt.Errorf("%s", msg)
	}
}

// lookupRole resolves a role by ARN or by name (optionally scoped to an account).
func lookupRole(ctx context.Context, s *store.Store, nameOrARN, accountID string) (*models.Role, error) {
	if len(nameOrARN) >= 3 && nameOrARN[:3] == "arn" {
		return s.GetRole(ctx, CustomerID, nameOrARN)
	}
	return s.GetRoleByName(ctx, CustomerID, nameOrARN, accountID)
}

// Debug is bound to the global --debug flag; TRAILTOOL_DEBUG=1 also enables it.
// When on, AWS/service errors surface the raw SDK error (request id, exception
// type, HTTP status) in addition to the human message (§5).
var Debug = false

func debugEnabled() bool {
	return Debug || os.Getenv("TRAILTOOL_DEBUG") == "1"
}

// fatal renders a one-line validation error ("Error: <msg>") to stderr and exits
// 1 (§5). Styling is resolved through the render context so the error is Fail-
// colored on a TTY and plain when redirected.
func fatal(format string, args ...interface{}) error {
	rctx := renderContext()
	fmt.Fprintln(rctx.Err, rctx.Error(fmt.Sprintf(format, args...)))
	os.Exit(1)
	return nil
}

// fatalAWS renders an AWS/service error as a human message plus a one-line hint,
// hiding the raw SDK error unless debug is on (§5), then exits 1. Use this for
// store-connection and store-query failures where the raw error is noise to a
// normal user but essential when diagnosing.
func fatalAWS(hint string, err error) error {
	rctx := renderContext()
	msg := "could not reach TrailTool data"
	fmt.Fprintln(rctx.Err, rctx.ErrorHint(msg, hint))
	if debugEnabled() {
		fmt.Fprintln(rctx.Err, "  "+rctx.Style(render.Muted, err.Error()))
	}
	os.Exit(1)
	return nil
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
