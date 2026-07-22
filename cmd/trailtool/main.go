package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/policy"
	"github.com/engseclabs/trailtool/core/session"
	"github.com/engseclabs/trailtool/core/store"
)

var version = "dev"

var customerID = "default"

func init() {
	if id := os.Getenv("TRAILTOOL_CUSTOMER_ID"); id != "" {
		customerID = id
	}
}

var format string

// relativeTime returns a human-friendly string like "2h ago", "3 days ago", "just now".
func relativeTime(ts string) string {
	if ts == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d mins ago", mins)
	case d < 24*time.Hour:
		hrs := int(d.Hours())
		if hrs == 1 {
			return "1 hr ago"
		}
		return fmt.Sprintf("%d hrs ago", hrs)
	case d < 48*time.Hour:
		return "yesterday"
	default:
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d days ago", days)
	}
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "trailtool",
		Short: "TrailTool - AWS CloudTrail analysis CLI",
		Long:  "Analyze AWS CloudTrail data for people, sessions, accounts, roles, services, and resources.",
	}

	rootCmd.PersistentFlags().StringVar(&format, "format", "text", "Output format: text or json")

	rootCmd.Version = version
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(peopleCmd())
	rootCmd.AddCommand(sessionsCmd())
	rootCmd.AddCommand(accountsCmd())
	rootCmd.AddCommand(rolesCmd())
	rootCmd.AddCommand(servicesCmd())
	rootCmd.AddCommand(resourcesCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- status ---

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check that TrailTool is set up and working",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ok := true

			// 1. Check AWS credentials
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				fmt.Println("AWS credentials: FAIL")
				fmt.Fprintf(os.Stderr, "  Could not load AWS config: %v\n", err)
				fmt.Fprintf(os.Stderr, "  Set AWS_PROFILE and AWS_REGION, then re-authenticate.\n")
				ok = false
			} else {
				stsClient := sts.NewFromConfig(cfg)
				identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				if err != nil {
					fmt.Println("AWS credentials: FAIL")
					fmt.Fprintf(os.Stderr, "  %v\n", err)
					fmt.Fprintf(os.Stderr, "  Set AWS_PROFILE and AWS_REGION, then re-authenticate.\n")
					ok = false
				} else {
					fmt.Printf("AWS credentials: OK (account %s)\n", aws.ToString(identity.Account))
				}

				// 2. Check CloudFormation stack
				if err == nil {
					cfnClient := cloudformation.NewFromConfig(cfg)
					stackFound := false
					for _, name := range []string{"trailtool-ingestor", "trailtool", "sam-app"} {
						_, err := cfnClient.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
							StackName: aws.String(name),
						})
						if err == nil {
							fmt.Printf("Ingestor stack: OK (%s)\n", name)
							stackFound = true
							break
						}
					}
					if !stackFound {
						fmt.Println("Ingestor stack: NOT FOUND")
						fmt.Fprintf(os.Stderr, "  No 'trailtool-ingestor', 'trailtool', or 'sam-app' CloudFormation stack found.\n")
						fmt.Fprintf(os.Stderr, "  Deploy the ingestor first: https://github.com/engseclabs/trailtool\n")
						ok = false
					}
				}
			}

			// 3. Check DynamoDB connectivity (try listing people)
			s, err := store.NewStore(ctx)
			if err == nil {
				_, err = s.ListPeople(ctx, customerID)
				if err != nil {
					fmt.Println("Data access: FAIL")
					fmt.Fprintf(os.Stderr, "  Could not query DynamoDB: %v\n", err)
					ok = false
				} else {
					fmt.Println("Data access: OK")
				}
			} else {
				fmt.Println("Data access: FAIL")
				fmt.Fprintf(os.Stderr, "  Could not connect to the data store: %v\n", err)
				ok = false
			}

			if !ok {
				os.Exit(1)
			}
			return nil
		},
	}
}

// --- people ---

func peopleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "people",
		Short: "People tracked in CloudTrail",
	}
	cmd.AddCommand(peopleListCmd())
	return cmd
}

func peopleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked people",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			people, err := s.ListPeople(ctx, customerID)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				return printJSON(people)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tPERSON\tKEY\tSESSIONS\tROLES\tACCOUNTS\tLAST SEEN")
			for i, p := range people {
				fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%s\n",
					i+1, p.DisplayLabel(), shortPersonKey(p.PersonKey), p.SessionsCount, p.RolesCount, p.AccountsCount, p.LastSeen)
			}
			return w.Flush()
		},
	}
}

// --- sessions ---

func sessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "CloudTrail sessions",
	}
	cmd.AddCommand(sessionsListCmd())
	cmd.AddCommand(sessionsDetailCmd())
	cmd.AddCommand(sessionsSummarizeCmd())
	cmd.AddCommand(sessionsPolicyCmd())
	return cmd
}

func sessionsListCmd() *cobra.Command {
	var user string
	var days int
	var role string
	var account string
	var after string
	var before string
	var tags []string
	var long bool
	var reverse bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			filter := store.SessionFilter{
				Days:      days,
				Role:      role,
				AccountID: account,
				After:     after,
				Before:    before,
			}

			sessions, personKeys, err := session.ListSessions(ctx, s, customerID, user, filter)
			if err != nil {
				return fatal("%v", err)
			}
			if user != "" && len(personKeys) > 1 {
				fmt.Fprintf(os.Stderr, "note: %d identities matched %s\n", len(personKeys), user)
			}

			// Apply --tag KEY=VALUE filters (all must match — AND semantics)
			if len(tags) > 0 {
				tagFilters, parseErr := parseTagFilters(tags)
				if parseErr != nil {
					return fatal("%v", parseErr)
				}
				filtered := sessions[:0]
				for _, sess := range sessions {
					if sessionMatchesTags(sess.SessionTags, tagFilters) {
						filtered = append(filtered, sess)
					}
				}
				sessions = filtered
			}

			if reverse {
				for i, j := 0, len(sessions)-1; i < j; i, j = i+1, j-1 {
					sessions[i], sessions[j] = sessions[j], sessions[i]
				}
			}

			if format == "json" {
				return printJSON(sessions)
			}

			label := personLabels(ctx, s)
			sidWidth := sidDisplayWidth(sessions)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SID\tWHEN\tUSER\tROLE\tACCOUNT\tEVENTS\tTYPE\tDURATION\tCHAINED")
			for i := range sessions {
				sess := &sessions[i]
				st := sess.DetectSessionType()
				duration := fmt.Sprintf("%dm", sess.DurationMinutes)
				chained := chainedMarks(sess)
				displayRole := sess.RoleName
				if !long {
					displayRole = shortRoleName(sess.RoleName)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
					shortSid(sess, sidWidth), relativeTime(sess.StartTime), label(sess.PersonKey), displayRole, sess.AccountID,
					sess.EventsCount, st, duration, chained)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "Filter by user email")
	cmd.Flags().IntVar(&days, "days", 0, "Filter to last N days")
	cmd.Flags().StringVar(&role, "role", "", "Filter by role name (substring match)")
	cmd.Flags().StringVar(&account, "account", "", "Filter by AWS account ID")
	cmd.Flags().StringVar(&after, "after", "", "Only sessions starting at or after this time (ISO8601)")
	cmd.Flags().StringVar(&before, "before", "", "Only sessions starting before this time (ISO8601)")
	cmd.Flags().StringArrayVar(&tags, "tag", nil, "Filter by session tag KEY=VALUE (repeatable, AND semantics)")
	cmd.Flags().BoolVar(&long, "long", false, "Show full role names instead of shortened SSO permission-set names")
	cmd.Flags().BoolVar(&reverse, "reverse", false, "Show newest sessions first (default is oldest first)")

	return cmd
}

// chainedMarks renders the CHAINED column: the session's relationships to other
// sessions, each naming the other end by its short SID so the two rows of an edge
// cross-reference regardless of list ordering or filters. A "←" mark points at the
// session that created this one; a "→" mark points at what this session created.
// The verb ("assumed"/"granted") carries the direction, so the glyph is redundant
// reinforcement rather than the sole cue. A session may be both a parent and a
// child (a chained session that further chains), so marks accumulate.
func chainedMarks(sess *models.Session) string {
	var marks []string

	// Incoming edges — how this session was created.
	if ref := sess.AgentAuthorizedBySession; ref != "" && ref != sess.Ref() {
		marks = append(marks, "← granted by "+sidForRefShort(ref))
	} else if ref := sess.LoginGrantedBySession; ref != "" {
		marks = append(marks, "← granted by "+sidForRefShort(ref))
	}
	if ref := sess.AssumedFromSession; ref != "" {
		marks = append(marks, "← assumed by "+sidForRefShort(ref))
	}

	// Outgoing edges — what this session created. When there's exactly one target
	// we name it by SID; for several we fall back to a count (the detail view lists
	// them). ChainedSessionRefs is preferred over ChainedRoles because a ref
	// resolves to a concrete child session; ChainedRoles is the ref-less fallback.
	if refs := sess.ChainedSessionRefs; len(refs) == 1 {
		marks = append(marks, "→ assumed "+sidForRefShort(refs[0]))
	} else if n := len(refs); n > 1 {
		marks = append(marks, fmt.Sprintf("→ assumed %d roles", n))
	} else if n := len(sess.ChainedRoles); n > 0 {
		marks = append(marks, fmt.Sprintf("→ assumed %d roles", n))
	}
	if refs := sess.GrantedSessionRefs; len(refs) == 1 {
		marks = append(marks, "→ granted "+sidForRefShort(refs[0]))
	} else if n := len(refs); n > 1 {
		marks = append(marks, fmt.Sprintf("→ granted %d sessions", n))
	}

	return strings.Join(marks, "  ")
}

var ssoRoleRe = regexp.MustCompile(`^aws-reserved/sso\.amazonaws\.com/[^/]+/AWSReservedSSO_([^_]+)_[0-9a-f]+$`)

// shortRoleName returns a shortened display name for SSO-managed roles.
// For aws-reserved/sso.amazonaws.com/.../AWSReservedSSO_<Name>_<hash>, it returns <Name>.
func shortRoleName(name string) string {
	if m := ssoRoleRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return name
}

// parseTagFilters parses a slice of "KEY=VALUE" strings into a map.
func parseTagFilters(raw []string) (map[string]string, error) {
	result := make(map[string]string, len(raw))
	for _, kv := range raw {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			return nil, fmt.Errorf("invalid --tag %q: expected KEY=VALUE", kv)
		}
		result[kv[:idx]] = kv[idx+1:]
	}
	return result, nil
}

// sessionMatchesTags returns true when all filters are present and match in the session tags.
func sessionMatchesTags(sessionTags map[string]string, filters map[string]string) bool {
	for k, v := range filters {
		if sessionTags[k] != v {
			return false
		}
	}
	return true
}

// shortPersonKey trims the noisy middle out of person keys for display:
// "email#alice@x.com" → "alice@x.com" stays readable via labels; idc# keys
// keep their tier prefix plus the trailing userId segment.
func shortPersonKey(key string) string {
	if rest, ok := strings.CutPrefix(key, "idc#"); ok {
		if idx := strings.LastIndex(rest, "#"); idx >= 0 {
			return "idc#…" + rest[idx:]
		}
	}
	return key
}

// personLabels fetches the people table once and returns a resolver mapping
// person keys to their friendliest display label (display name, email, or the
// key itself).
func personLabels(ctx context.Context, s *store.Store) func(string) string {
	labels := map[string]string{}
	if people, err := s.ListPeople(ctx, customerID); err == nil {
		for i := range people {
			labels[people[i].PersonKey] = people[i].DisplayLabel()
		}
	}
	return func(key string) string {
		if l, ok := labels[key]; ok && l != "" {
			return l
		}
		return shortPersonKey(key)
	}
}

// refPersonKey returns the person-key half of a session ref ("person_key|sk").
func refPersonKey(ref string) string {
	if personKey, _, ok := strings.Cut(ref, "|"); ok {
		return personKey
	}
	return ref
}

// printRefNav prints one attribution line (who + when) for a session ref,
// followed by a copy-pasteable detail command when the target is fetchable.
func printRefNav(ctx context.Context, s *store.Store, heading, ref string, label func(string) string) {
	who := label(refPersonKey(ref))
	target, err := s.GetSessionByRef(ctx, customerID, ref)
	if err != nil || target == nil {
		fmt.Printf("%s: %s\n", heading, who)
		return
	}
	fmt.Printf("%s: %s at %s [%s]\n", heading, who, target.StartTime, relativeTime(target.StartTime))
	fmt.Printf("  → trailtool sessions detail --session %s\n", sidForRefShort(ref))
}

// sidDisplayWidth returns the shortest prefix length (≥ sidDisplayMin) at
// which every session's sid stays unique within the given list, so every SID the
// CLI prints is copy-pasteable and unambiguous against what's on screen. Sessions
// without a stored sid (pre-sid records) are ignored for width purposes.
func sidDisplayWidth(sessions []models.Session) int {
	width := sidDisplayMin
	for {
		seen := make(map[string]bool, len(sessions))
		clash := false
		for i := range sessions {
			sid := sessions[i].Sid
			if sid == "" {
				continue
			}
			p := sid[:min(len(sid), width)]
			if seen[p] {
				clash = true
				break
			}
			seen[p] = true
		}
		if !clash || width >= sidFullLen {
			return width
		}
		width++
	}
}

// shortSid renders a session's sid at the given display width, or a placeholder
// when the record predates sids.
func shortSid(sess *models.Session, width int) string {
	if sess.Sid == "" {
		return "-"
	}
	return sess.Sid[:min(len(sess.Sid), width)]
}

// sidForRefShort renders the display-width sid for a session ref (person_key|sk),
// for drilldown hints that point at another session without fetching it.
func sidForRefShort(ref string) string {
	return models.SidForRef(ref)[:sidDisplayMin]
}

// sid display/lookup constants, mirrored from ingestor identity.Sid.
const (
	sidDisplayMin = 6
	sidFullLen    = 16
)

// resolveSession finds a single session by --session: a sid prefix, or "latest".
// An empty prefix, no match, or an ambiguous prefix each return an actionable
// error.
func resolveSession(ctx context.Context, s *store.Store, sel, user string) (*models.Session, error) {
	if sel == "latest" {
		filter := store.SessionFilter{Days: 90}
		sessions, _, err := session.ListSessions(ctx, s, customerID, user, filter)
		if err != nil {
			return nil, err
		}
		if len(sessions) == 0 {
			return nil, fmt.Errorf("no sessions found")
		}
		latest := sessions[len(sessions)-1]
		return &latest, nil
	}

	matches, err := s.FindSessionsBySidPrefix(ctx, customerID, sel)
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
		width := sidDisplayWidth(matches)
		if width <= len(sel) {
			width = len(sel) + 1
		}
		label := personLabels(ctx, s)
		msg := fmt.Sprintf("%d sessions match id %q — use a longer id:\n", len(matches), sel)
		for i := range matches {
			m := &matches[i]
			msg += fmt.Sprintf("  %s  %s  %s  %s\n",
				shortSid(m, width), m.StartTime, label(m.PersonKey), m.RoleName)
		}
		return nil, fmt.Errorf("%s", msg)
	}
}

func sessionsDetailCmd() *cobra.Command {
	var sessionID string
	var user string

	cmd := &cobra.Command{
		Use:   "detail",
		Short: "Show session details",
		Long: `Show details for a session identified by its id (the SID column from
'trailtool sessions list'). A short prefix is enough; "latest" jumps to the
most recent session.

Examples:
  trailtool sessions detail --session k7m2qp
  trailtool sessions detail --session latest
  trailtool sessions detail --session latest --user alice@example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sessionID == "" {
				return fatal("--session is required (e.g. --session k7m2qp or --session latest)")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			sess, err := resolveSession(ctx, s, sessionID, user)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				return printJSON(sess)
			}

			label := personLabels(ctx, s)
			fmt.Printf("User: %s (%s)\n", label(sess.PersonKey), sess.PersonKey)
			fmt.Printf("Role: %s (%s)\n", sess.RoleName, sess.RoleARN)
			fmt.Printf("Account: %s\n", sess.AccountID)
			fmt.Printf("Type: %s\n", sess.DetectSessionType())
			fmt.Printf("Session: %s\n", sess.SK)
			fmt.Printf("Time: %s -> %s (%dm) [%s]\n", sess.StartTime, sess.EndTime, sess.DurationMinutes, relativeTime(sess.StartTime))
			fmt.Printf("Events: %d across %d services\n", sess.EventsCount, sess.ServicesCount)
			if sess.ServiceDrivenEventCount > 0 {
				fmt.Printf("Service-driven events: %d (AWS services calling with these credentials)\n", sess.ServiceDrivenEventCount)
			}

			if len(sess.SessionTags) > 0 {
				fmt.Println("\nSession Tags:")
				tagKeys := make([]string, 0, len(sess.SessionTags))
				for k := range sess.SessionTags {
					tagKeys = append(tagKeys, k)
				}
				sort.Strings(tagKeys)
				for _, k := range tagKeys {
					fmt.Printf("  %s: %s\n", k, sess.SessionTags[k])
				}
			}

			if sess.DeniedEventCount > 0 {
				fmt.Printf("Denied Events: %d\n", sess.DeniedEventCount)
			}

			if len(sess.EventCounts) > 0 {
				fmt.Println("\nTop Events:")
				eventKeys := make([]string, 0, len(sess.EventCounts))
				for k := range sess.EventCounts {
					eventKeys = append(eventKeys, k)
				}
				sort.Strings(eventKeys)
				for _, event := range eventKeys {
					fmt.Printf("  %s: %d\n", event, sess.EventCounts[event])
				}
			}

			if len(sess.ResourcesAccessed) > 0 {
				fmt.Println("\nResources Accessed:")
				resourceKeys := make([]string, 0, len(sess.ResourcesAccessed))
				for k := range sess.ResourcesAccessed {
					resourceKeys = append(resourceKeys, k)
				}
				sort.Strings(resourceKeys)
				for _, resource := range resourceKeys {
					fmt.Printf("  %s: %d\n", resource, sess.ResourcesAccessed[resource])
				}
			}

			// AWS MCP Server agent traffic: show the MCP resource and the human session that
			// authorized the OAuth grant these agent credentials were minted under.
			if sess.AgentAuthorizedBySession != "" || sess.MCPResource != "" {
				if sess.MCPResource != "" {
					fmt.Printf("\nAWS MCP Server: %s\n", sess.MCPResource)
				}
				if sess.SignInSessionArn != "" {
					fmt.Printf("Sign-in session: %s\n", sess.SignInSessionArn)
				}
				if sess.AgentAuthorizedBySession != "" && sess.AgentAuthorizedBySession != sess.Ref() {
					printRefNav(ctx, s, "OAuth grant authorized by", sess.AgentAuthorizedBySession, label)
				}
			}

			// Login grant: show the human session that ran aws login to create these credentials
			if sess.LoginGrantedBySession != "" {
				fmt.Println()
				printRefNav(ctx, s, "Credentials granted via aws login by", sess.LoginGrantedBySession, label)
			}

			// Chaining: child view — show parent with navigable time
			if sess.AssumedFromSession != "" {
				fmt.Println()
				printRefNav(ctx, s, "Assumed by", sess.AssumedFromSession, label)
			}

			// Chaining: parent view — show each child session with navigable time
			if len(sess.ChainedSessionRefs) > 0 || len(sess.ChainedRoles) > 0 {
				fmt.Printf("\nAssumed Roles (%d, %d events):\n", len(sess.ChainedRoles), sess.ChainedEventCount)
				shown := 0
				for _, childRef := range sess.ChainedSessionRefs {
					childSess, _ := s.GetSessionByRef(ctx, customerID, childRef)
					if childSess == nil {
						fmt.Printf("  %s\n", childRef)
						continue
					}
					shown++
					fmt.Printf("  %s  %-25s  %d events  %dm  [%s]\n",
						childSess.StartTime, childSess.RoleName,
						childSess.EventsCount, childSess.DurationMinutes,
						relativeTime(childSess.StartTime))
					fmt.Printf("    → trailtool sessions detail --session %s\n", sidForRefShort(childRef))
				}
				if shown == 0 && len(sess.ChainedSessionRefs) == 0 {
					for _, childRoleARN := range sess.ChainedRoles {
						fmt.Printf("  %s\n", childRoleARN)
					}
				}
			}

			// Grants: parent view — sessions whose credentials this session
			// authorized via aws login / MCP OAuth grants.
			if len(sess.GrantedSessionRefs) > 0 {
				fmt.Printf("\nAuthorized Sessions (%d):\n", len(sess.GrantedSessionRefs))
				for _, gRef := range sess.GrantedSessionRefs {
					gSess, _ := s.GetSessionByRef(ctx, customerID, gRef)
					if gSess == nil {
						fmt.Printf("  %s\n", gRef)
						continue
					}
					fmt.Printf("  %s  %-5s  %-25s  %d events  %dm  [%s]\n",
						gSess.StartTime, gSess.DetectSessionType(), shortRoleName(gSess.RoleName),
						gSess.EventsCount, gSess.DurationMinutes, relativeTime(gSess.StartTime))
					fmt.Printf("    → trailtool sessions detail --session %s\n", sidForRefShort(gRef))
				}
			}

			if sess.SessionPolicy != "" {
				fmt.Println("\nSession Policy:")
				prettyPolicy, ppErr := prettyJSON(sess.SessionPolicy)
				if ppErr != nil {
					fmt.Printf("  %s\n", sess.SessionPolicy)
				} else {
					for _, line := range strings.Split(prettyPolicy, "\n") {
						fmt.Printf("  %s\n", line)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Session id from the SID column (prefix ok), or \"latest\"")
	cmd.Flags().StringVar(&user, "user", "", "Filter by user email (only with --session latest)")

	return cmd
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// prettyJSON re-indents a JSON string. Returns an error if input is not valid JSON.
func prettyJSON(raw string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func sessionsSummarizeCmd() *cobra.Command {
	var sessionID string
	var user string

	cmd := &cobra.Command{
		Use:   "summarize",
		Short: "Generate AI summary of a session via Bedrock",
		Long: `Generate an AI summary of a session identified by its id (the SID column
from 'trailtool sessions list'). A short prefix is enough; "latest" jumps to
the most recent session.

Examples:
  trailtool sessions summarize --session k7m2qp
  trailtool sessions summarize --session latest
  trailtool sessions summarize --session latest --user alice@example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sessionID == "" {
				return fatal("--session is required (e.g. --session k7m2qp or --session latest)")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			sess, err := resolveSession(ctx, s, sessionID, user)
			if err != nil {
				return fatal("%v", err)
			}

			// Check for cached summary
			if sess.Summary != "" {
				if format == "json" {
					return printJSON(map[string]string{
						"summary":      sess.Summary,
						"generated_at": sess.SummaryGeneratedAt,
						"model":        sess.SummaryModel,
						"cached":       "true",
					})
				}
				fmt.Println(sess.Summary)
				return nil
			}

			summary, err := session.SummarizeSession(ctx, sess)
			if err != nil {
				return fatal("bedrock invocation failed: %v", err)
			}

			if format == "json" {
				return printJSON(map[string]string{
					"summary": summary,
					"cached":  "false",
				})
			}
			fmt.Println(summary)
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Session id from the SID column (prefix ok), or \"latest\"")
	cmd.Flags().StringVar(&user, "user", "", "Filter by user email (only with --session latest)")

	return cmd
}

func sessionsPolicyCmd() *cobra.Command {
	var sessionID string
	var user string
	var includeDenied bool
	var explain bool

	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Generate least-privilege IAM policy for a session",
		Long: `Generate a least-privilege IAM policy scoped to a specific session,
identified by its id (the SID column from 'trailtool sessions list'). A short
prefix is enough; "latest" jumps to the most recent session.

Examples:
  trailtool sessions policy --session k7m2qp
  trailtool sessions policy --session latest --user alice@example.com
  trailtool sessions policy --session k7m2qp --include-denied --explain`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sessionID == "" {
				return fatal("--session is required (e.g. --session k7m2qp or --session latest)")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			sess, err := resolveSession(ctx, s, sessionID, user)
			if err != nil {
				return fatal("%v", err)
			}

			result, err := policy.GeneratePolicyFromSession(sess, includeDenied)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				return printJSON(result)
			}

			fmt.Println(result.PolicyJSON)

			if explain {
				fmt.Fprintf(os.Stderr, "\n--- Policy Summary ---\n")
				fmt.Fprintf(os.Stderr, "Session: %s\n", result.SessionID)
				fmt.Fprintf(os.Stderr, "Role: %s (%s)\n", result.RoleName, result.RoleARN)
				fmt.Fprintf(os.Stderr, "Total unique IAM actions: %d\n", result.TotalActionsUsed)
				if len(result.UnmappedEvents) > 0 {
					fmt.Fprintf(os.Stderr, "Unmapped CloudTrail events: %d\n", len(result.UnmappedEvents))
					for _, e := range result.UnmappedEvents {
						fmt.Fprintf(os.Stderr, "  - %s\n", e)
					}
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Session id from the SID column (prefix ok), or \"latest\"")
	cmd.Flags().StringVar(&user, "user", "", "Filter by user email (only with --session latest)")
	cmd.Flags().BoolVar(&includeDenied, "include-denied", false, "Include denied events in policy")
	cmd.Flags().BoolVar(&explain, "explain", false, "Show policy explanation on stderr")

	return cmd
}

// --- accounts ---

func accountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "AWS accounts",
	}
	cmd.AddCommand(accountsListCmd())
	cmd.AddCommand(accountsDetailCmd())
	return cmd
}

func accountsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked AWS accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			accounts, err := s.ListAccounts(ctx, customerID)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				return printJSON(accounts)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tACCOUNT ID\tNAME\tPEOPLE\tSESSIONS\tROLES\tSERVICES\tRESOURCES\tLAST SEEN")
			for i, a := range accounts {
				fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
					i+1, a.AccountID, a.AccountName, a.PeopleCount, a.SessionsCount,
					a.RolesCount, a.ServicesCount, a.ResourcesCount, a.LastSeen)
			}
			return w.Flush()
		},
	}
}

func accountsDetailCmd() *cobra.Command {
	var index int

	cmd := &cobra.Command{
		Use:   "detail [account-id]",
		Short: "Show account details",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && index == 0 {
				return fatal("account-id argument or --index is required")
			}
			if len(args) > 0 && index != 0 {
				return fatal("account-id argument and --index are mutually exclusive")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			var accountID string
			if index != 0 {
				accounts, listErr := s.ListAccounts(ctx, customerID)
				if listErr != nil {
					return fatal("%v", listErr)
				}
				if index < 1 || index > len(accounts) {
					return fatal("--index %d out of range (1-%d)", index, len(accounts))
				}
				accountID = accounts[index-1].AccountID
			} else {
				accountID = args[0]
			}

			account, err := s.GetAccount(ctx, customerID, accountID)
			if err != nil {
				return fatal("%v", err)
			}
			if account == nil {
				return fatal("account not found: %s", accountID)
			}

			if format == "json" {
				return printJSON(account)
			}

			fmt.Printf("Account: %s\n", account.AccountID)
			if account.AccountName != "" {
				fmt.Printf("Name: %s\n", account.AccountName)
			}
			fmt.Printf("First Seen: %s\n", account.FirstSeen)
			fmt.Printf("Last Seen: %s\n", account.LastSeen)
			fmt.Printf("People: %d\n", account.PeopleCount)
			fmt.Printf("Sessions: %d\n", account.SessionsCount)
			fmt.Printf("Roles: %d\n", account.RolesCount)
			fmt.Printf("Services: %d\n", account.ServicesCount)
			fmt.Printf("Resources: %d\n", account.ResourcesCount)
			fmt.Printf("Events: %d\n", account.EventsCount)

			return nil
		},
	}

	cmd.Flags().IntVar(&index, "index", 0, "Select account by list index (from 'accounts list')")

	return cmd
}

// --- roles ---

func rolesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "IAM roles",
	}
	cmd.AddCommand(rolesListCmd())
	cmd.AddCommand(rolesDetailCmd())
	cmd.AddCommand(rolesPolicyCmd())
	return cmd
}

func rolesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked IAM roles",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			roles, err := s.ListRoles(ctx, customerID)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				return printJSON(roles)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tNAME\tACCOUNT\tEVENTS\tPEOPLE\tSESSIONS\tDENIED\tLAST SEEN")
			for i, r := range roles {
				fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
					i+1, r.Name, r.AccountID, r.TotalEvents, r.PeopleCount,
					r.SessionsCount, r.TotalDeniedEvents, r.LastSeen)
			}
			return w.Flush()
		},
	}
}

func rolesDetailCmd() *cobra.Command {
	var accountID string
	var index int

	cmd := &cobra.Command{
		Use:   "detail [role-name-or-arn]",
		Short: "Show role details",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && index == 0 {
				return fatal("role-name-or-arn argument or --index is required")
			}
			if len(args) > 0 && index != 0 {
				return fatal("role-name-or-arn argument and --index are mutually exclusive")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			var role *models.Role
			if index != 0 {
				roles, listErr := s.ListRoles(ctx, customerID)
				if listErr != nil {
					return fatal("%v", listErr)
				}
				if index < 1 || index > len(roles) {
					return fatal("--index %d out of range (1-%d)", index, len(roles))
				}
				role, err = lookupRole(ctx, s, roles[index-1].ARN, accountID)
			} else {
				role, err = lookupRole(ctx, s, args[0], accountID)
			}
			if err != nil {
				return fatal("%v", err)
			}
			if role == nil {
				return fatal("role not found")
			}

			if format == "json" {
				return printJSON(role)
			}

			fmt.Printf("Role: %s\n", role.Name)
			fmt.Printf("ARN: %s\n", role.ARN)
			fmt.Printf("Account: %s\n", role.AccountID)
			fmt.Printf("First Seen: %s\n", role.FirstSeen)
			fmt.Printf("Last Seen: %s\n", role.LastSeen)
			fmt.Printf("Total Events: %d\n", role.TotalEvents)
			fmt.Printf("People: %d\n", role.PeopleCount)
			fmt.Printf("Sessions: %d\n", role.SessionsCount)

			if role.TotalDeniedEvents > 0 {
				fmt.Printf("Denied Events: %d\n", role.TotalDeniedEvents)
			}

			if len(role.ServicesUsed) > 0 {
				fmt.Println("\nServices Used:")
				sortedSvcs := make([]string, len(role.ServicesUsed))
				copy(sortedSvcs, role.ServicesUsed)
				sort.Strings(sortedSvcs)
				for _, svc := range sortedSvcs {
					fmt.Printf("  %s\n", svc)
				}
			}

			if len(role.TopEventNames) > 0 {
				fmt.Println("\nTop Events:")
				roleEventKeys := make([]string, 0, len(role.TopEventNames))
				for k := range role.TopEventNames {
					roleEventKeys = append(roleEventKeys, k)
				}
				sort.Strings(roleEventKeys)
				for _, event := range roleEventKeys {
					fmt.Printf("  %s: %d\n", event, role.TopEventNames[event])
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&accountID, "account", "", "Filter by AWS account ID (disambiguates roles with the same name)")
	cmd.Flags().IntVar(&index, "index", 0, "Select role by list index (from 'roles list')")

	return cmd
}

func rolesPolicyCmd() *cobra.Command {
	var includeDenied bool
	var explain bool
	var accountID string

	cmd := &cobra.Command{
		Use:   "policy [role-name-or-arn]",
		Short: "Generate least-privilege IAM policy for a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			role, err := lookupRole(ctx, s, args[0], accountID)
			if err != nil {
				return fatal("%v", err)
			}
			if role == nil {
				return fatal("role not found: %s", args[0])
			}

			result, err := policy.GeneratePolicy(role, includeDenied)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				return printJSON(result)
			}

			fmt.Println(result.PolicyJSON)

			if explain {
				fmt.Fprintf(os.Stderr, "\n--- Policy Summary ---\n")
				fmt.Fprintf(os.Stderr, "Role: %s (%s)\n", result.RoleName, result.RoleARN)
				fmt.Fprintf(os.Stderr, "Total unique IAM actions: %d\n", result.TotalActionsUsed)
				if len(result.UnmappedEvents) > 0 {
					fmt.Fprintf(os.Stderr, "Unmapped CloudTrail events: %d\n", len(result.UnmappedEvents))
					for _, e := range result.UnmappedEvents {
						fmt.Fprintf(os.Stderr, "  - %s\n", e)
					}
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&includeDenied, "include-denied", false, "Include denied events in policy")
	cmd.Flags().BoolVar(&explain, "explain", false, "Show policy explanation on stderr")
	cmd.Flags().StringVar(&accountID, "account", "", "Filter by AWS account ID (disambiguates roles with the same name)")

	return cmd
}

// --- services ---

func servicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "services",
		Short: "AWS services",
	}
	cmd.AddCommand(servicesListCmd())
	cmd.AddCommand(servicesDetailCmd())
	return cmd
}

func servicesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked AWS services",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			services, err := s.ListServices(ctx, customerID)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				return printJSON(services)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tSERVICE\tDISPLAY NAME\tEVENTS\tROLES\tRESOURCES\tPEOPLE\tLAST SEEN")
			for i, svc := range services {
				fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
					i+1, svc.EventSource, svc.DisplayName, svc.TotalEvents,
					svc.RolesCount, svc.ResourcesCount, svc.PeopleCount, svc.LastSeen)
			}
			return w.Flush()
		},
	}
}

func servicesDetailCmd() *cobra.Command {
	var index int

	cmd := &cobra.Command{
		Use:   "detail [event-source]",
		Short: "Show service details",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && index == 0 {
				return fatal("event-source argument or --index is required")
			}
			if len(args) > 0 && index != 0 {
				return fatal("event-source argument and --index are mutually exclusive")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			var eventSource string
			if index != 0 {
				services, listErr := s.ListServices(ctx, customerID)
				if listErr != nil {
					return fatal("%v", listErr)
				}
				if index < 1 || index > len(services) {
					return fatal("--index %d out of range (1-%d)", index, len(services))
				}
				eventSource = services[index-1].EventSource
			} else {
				eventSource = args[0]
			}

			svc, err := s.GetService(ctx, customerID, eventSource)
			if err != nil {
				return fatal("%v", err)
			}
			if svc == nil {
				return fatal("service not found: %s", eventSource)
			}

			if format == "json" {
				return printJSON(svc)
			}

			fmt.Printf("Service: %s\n", svc.EventSource)
			if svc.DisplayName != "" {
				fmt.Printf("Display Name: %s\n", svc.DisplayName)
			}
			if svc.Category != "" {
				fmt.Printf("Category: %s\n", svc.Category)
			}
			fmt.Printf("First Seen: %s\n", svc.FirstSeen)
			fmt.Printf("Last Seen: %s\n", svc.LastSeen)
			fmt.Printf("Total Events: %d\n", svc.TotalEvents)
			fmt.Printf("Roles: %d\n", svc.RolesCount)
			fmt.Printf("Resources: %d\n", svc.ResourcesCount)
			fmt.Printf("People: %d\n", svc.PeopleCount)
			fmt.Printf("Sessions: %d\n", svc.SessionsCount)
			fmt.Printf("Accounts: %d\n", svc.AccountsCount)

			if svc.TotalDeniedEvents > 0 {
				fmt.Printf("Denied Events: %d\n", svc.TotalDeniedEvents)
			}

			if len(svc.TopEventNames) > 0 {
				fmt.Println("\nTop Events:")
				svcEventKeys := make([]string, 0, len(svc.TopEventNames))
				for k := range svc.TopEventNames {
					svcEventKeys = append(svcEventKeys, k)
				}
				sort.Strings(svcEventKeys)
				for _, event := range svcEventKeys {
					fmt.Printf("  %s: %d\n", event, svc.TopEventNames[event])
				}
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&index, "index", 0, "Select service by list index (from 'services list')")

	return cmd
}

// --- resources ---

func resourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resources",
		Short: "AWS resources",
	}
	cmd.AddCommand(resourcesListCmd())
	return cmd
}

func resourcesListCmd() *cobra.Command {
	var days int
	var serviceType string
	var clickops bool
	var minClickOps int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tracked AWS resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			filter := store.ResourceFilter{
				ClickOpsOnly:     clickops,
				ServiceType:      serviceType,
				MinClickOpsCount: minClickOps,
			}
			if days > 0 {
				filter.StartTime = time.Now().AddDate(0, 0, -days).Format("2006-01-02")
			}

			resources, err := s.ListResources(ctx, customerID, filter)
			if err != nil {
				return fatal("%v", err)
			}

			if format == "json" {
				if resources == nil {
					resources = []models.Resource{}
				}
				return printJSON(resources)
			}

			if len(resources) == 0 {
				fmt.Println("No resources found.")
				return nil
			}

			if clickops {
				fmt.Printf("Found %d resources created/modified via web console:\n\n", len(resources))

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "#\tRESOURCE\tTYPE\tACCOUNT\tCLICKOPS EVENTS\tLAST SEEN")
				for i, r := range resources {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\n",
						i+1, r.Name, r.Type, r.AccountID, r.ClickOpsCount, r.LastSeen)
				}
				w.Flush()

				label := personLabels(ctx, s)
				fmt.Println("\n--- Console Operations ---")
				for _, r := range resources {
					fmt.Printf("\n%s (%s)\n", r.Name, r.Type)
					for _, access := range r.ClickOpsAccesses {
						date := access.AccessTime
						if len(date) >= 10 {
							date = date[:10]
						}
						fmt.Printf("  %s by %s (%dx) - %s\n",
							access.EventName, label(access.PersonKey), access.EventCount, date)
					}
				}
			} else {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "#\tRESOURCE\tTYPE\tACCOUNT\tEVENTS\tCLICKOPS\tLAST SEEN")
				for i, r := range resources {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%d\t%s\n",
						i+1, r.Name, r.Type, r.AccountID, r.TotalEvents, r.ClickOpsCount, r.LastSeen)
				}
				w.Flush()
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&days, "days", 0, "Filter to last N days")
	cmd.Flags().StringVar(&serviceType, "service", "", "Filter by AWS service type (e.g. s3, lambda, ec2)")
	cmd.Flags().BoolVar(&clickops, "clickops", false, "Only show resources created/modified via web console")
	cmd.Flags().IntVar(&minClickOps, "min-clickops", 1, "Minimum ClickOps events (used with --clickops)")

	return cmd
}

// --- helpers ---

func lookupRole(ctx context.Context, s *store.Store, nameOrARN, accountID string) (*models.Role, error) {
	if len(nameOrARN) >= 3 && nameOrARN[:3] == "arn" {
		return s.GetRole(ctx, customerID, nameOrARN)
	}
	return s.GetRoleByName(ctx, customerID, nameOrARN, accountID)
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
