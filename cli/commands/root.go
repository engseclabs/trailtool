package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
// Global flag validation runs before commands reach this helper.
func renderContext() render.Context {
	mode, _ := render.ParseColorMode(ColorMode)
	return render.Detect(mode, os.Stdout, os.Stderr)
}

// ValidateGlobalFlags rejects unsupported output modes before a command loads
// AWS configuration or opens the data store.
func ValidateGlobalFlags() error {
	if Format != "text" && Format != "json" {
		return fmt.Errorf("invalid --format %q (want text or json)", Format)
	}
	if _, ok := render.ParseColorMode(ColorMode); !ok {
		return fmt.Errorf("invalid --color %q (want auto, always, or never)", ColorMode)
	}
	return nil
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

// resolveSession finds a single session by selector: a SID prefix, or "latest".
// An empty prefix, no match, or an ambiguous prefix each return an actionable
// error.
func resolveSession(ctx context.Context, s *store.Store, sel string) (*models.Session, error) {
	if sel == "latest" {
		sessions, _, err := session.ListSessions(ctx, s, CustomerID, "", store.SessionFilter{Limit: 1})
		if err != nil {
			return nil, err
		}
		return latestSession(sessions)
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
		now := time.Now()
		msg := fmt.Sprintf("%d sessions match id %q: use a longer id:\n", len(matches), sel)
		for i := range matches {
			m := &matches[i]
			msg += fmt.Sprintf("  %s  %s  %s  %s\n",
				view.ShortSid(m, width), render.Timestamp(m.StartTime, now), label(m.PersonKey), m.RoleName)
		}
		return nil, fmt.Errorf("%s", msg)
	}
}

func latestSession(sessions []models.Session) (*models.Session, error) {
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no sessions found")
	}
	models.SortSessionsForList(sessions, false)
	latest := sessions[len(sessions)-1]
	return &latest, nil
}

// lookupRole resolves the primary short role ID, then the full ARN or an exact
// role name. --account scopes only the name fallback.
func lookupRole(ctx context.Context, s *store.Store, selector, accountID string) (*models.Role, error) {
	if strings.HasPrefix(selector, "arn:") {
		return s.GetRole(ctx, CustomerID, selector)
	}
	matches, err := s.FindRolesByRoleIDPrefix(ctx, CustomerID, selector)
	if err != nil {
		return nil, err
	}
	role, err := resolveRoleIDMatches(selector, matches)
	if err != nil || role != nil {
		return role, err
	}
	return s.GetRoleByName(ctx, CustomerID, selector, accountID)
}

func resolveRoleIDMatches(selector string, matches []models.Role) (*models.Role, error) {
	switch len(matches) {
	case 0:
		return nil, nil
	case 1:
		return &matches[0], nil
	default:
		width := view.RoleIDDisplayWidth(matches)
		if width <= len(selector) {
			width = min(len(selector)+1, 16)
		}
		msg := fmt.Sprintf("%d roles match id %q: use a longer id:\n", len(matches), selector)
		for i := range matches {
			m := &matches[i]
			msg += fmt.Sprintf("  %s  %s  %s\n", view.ShortRoleID(m, width), m.AccountID, m.ARN)
		}
		return nil, fmt.Errorf("%s", msg)
	}
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
