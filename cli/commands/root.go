package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/session"
	"github.com/engseclabs/trailtool/core/store"
)

// Format holds the value of the global --format flag ("text" or "json"). It is
// bound by main.go's persistent flag registration.
var Format = "text"

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
// followed by a copy-pasteable detail command when the target is fetchable.
func printRefNav(ctx context.Context, s *store.Store, heading, ref string, label func(string) string) {
	who := label(view.RefPersonKey(ref))
	target, err := s.GetSessionByRef(ctx, CustomerID, ref)
	if err != nil || target == nil {
		fmt.Printf("%s: %s\n", heading, who)
		return
	}
	fmt.Printf("%s: %s at %s [%s]\n", heading, who, target.StartTime, view.RelativeTime(target.StartTime))
	fmt.Printf("  → trailtool sessions detail --session %s\n", view.SidForRefShort(ref))
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

func fatal(format string, args ...interface{}) error {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
	return nil
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
