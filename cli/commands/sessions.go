package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/policy"
	"github.com/engseclabs/trailtool/core/session"
	"github.com/engseclabs/trailtool/core/store"
)

func SessionsCmd() *cobra.Command {
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

			sessions, personKeys, err := session.ListSessions(ctx, s, CustomerID, user, filter)
			if err != nil {
				return fatal("%v", err)
			}
			if user != "" && len(personKeys) > 1 {
				fmt.Fprintf(os.Stderr, "note: %d identities matched %s\n", len(personKeys), user)
			}

			// Apply --tag KEY=VALUE filters (all must match — AND semantics)
			if len(tags) > 0 {
				tagFilters, parseErr := view.ParseTagFilters(tags)
				if parseErr != nil {
					return fatal("%v", parseErr)
				}
				filtered := sessions[:0]
				for _, sess := range sessions {
					if view.SessionMatchesTags(sess.SessionTags, tagFilters) {
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

			if Format == "json" {
				return printJSON(sessions)
			}

			label := personLabels(ctx, s)
			sidWidth := view.SidDisplayWidth(sessions)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SID\tWHEN\tUSER\tROLE\tACCOUNT\tEVENTS\tTYPE\tDURATION\tCHAINED")
			for i := range sessions {
				sess := &sessions[i]
				st := sess.DetectSessionType()
				duration := fmt.Sprintf("%dm", sess.DurationMinutes)
				chained := view.ChainedMarks(sess)
				displayRole := sess.RoleName
				if !long {
					displayRole = view.ShortRoleName(sess.RoleName)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
					view.ShortSid(sess, sidWidth), view.RelativeTime(sess.StartTime), label(sess.PersonKey), displayRole, sess.AccountID,
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

			if Format == "json" {
				return printJSON(sess)
			}

			label := personLabels(ctx, s)
			fmt.Printf("User: %s (%s)\n", label(sess.PersonKey), sess.PersonKey)
			fmt.Printf("Role: %s (%s)\n", sess.RoleName, sess.RoleARN)
			fmt.Printf("Account: %s\n", sess.AccountID)
			fmt.Printf("Type: %s\n", sess.DetectSessionType())
			fmt.Printf("Session: %s\n", sess.SK)
			fmt.Printf("Time: %s -> %s (%dm) [%s]\n", sess.StartTime, sess.EndTime, sess.DurationMinutes, view.RelativeTime(sess.StartTime))
			fmt.Printf("Events: %d across %d services\n", sess.EventsCount, sess.ServicesCount)
			if sess.ServiceDrivenEventCount > 0 {
				fmt.Printf("Service-driven events: %d (AWS services calling with these credentials)\n", sess.ServiceDrivenEventCount)
			}

			view.PrintClients(sess.Clients)

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
					childSess, _ := s.GetSessionByRef(ctx, CustomerID, childRef)
					if childSess == nil {
						fmt.Printf("  %s\n", childRef)
						continue
					}
					shown++
					fmt.Printf("  %s  %-25s  %d events  %dm  [%s]\n",
						childSess.StartTime, childSess.RoleName,
						childSess.EventsCount, childSess.DurationMinutes,
						view.RelativeTime(childSess.StartTime))
					fmt.Printf("    → trailtool sessions detail --session %s\n", view.SidForRefShort(childRef))
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
					gSess, _ := s.GetSessionByRef(ctx, CustomerID, gRef)
					if gSess == nil {
						fmt.Printf("  %s\n", gRef)
						continue
					}
					fmt.Printf("  %s  %-5s  %-25s  %d events  %dm  [%s]\n",
						gSess.StartTime, gSess.DetectSessionType(), view.ShortRoleName(gSess.RoleName),
						gSess.EventsCount, gSess.DurationMinutes, view.RelativeTime(gSess.StartTime))
					fmt.Printf("    → trailtool sessions detail --session %s\n", view.SidForRefShort(gRef))
				}
			}

			if sess.SessionPolicy != "" {
				fmt.Println("\nSession Policy:")
				prettyPolicy, ppErr := view.PrettyJSON(sess.SessionPolicy)
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
				if Format == "json" {
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

			if Format == "json" {
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

			if Format == "json" {
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
