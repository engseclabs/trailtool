package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/policy"
	"github.com/engseclabs/trailtool/core/session"
	"github.com/engseclabs/trailtool/core/store"
	"github.com/engseclabs/trailtool/internal/render"
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
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
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
			fmt.Print(view.SessionList(renderContext(), sessions, sidWidth, long, label, time.Now()))
			return nil
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
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			sess, err := resolveSession(ctx, s, sessionID, user)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				return printJSON(sess)
			}

			rctx := renderContext()
			now := time.Now()
			label := personLabels(ctx, s)

			// Title + key facts (§5). The time line uses the centralized interval +
			// relative rule (§4.5); the command owns "now".
			timeLine := fmt.Sprintf("%s (%dm) [%s]",
				rctx.Interval(sess.StartTime, sess.EndTime), sess.DurationMinutes, render.Relative(sess.StartTime, now))
			fmt.Print(view.SessionTitleKV(rctx, sess, label(sess.PersonKey), timeLine))

			// Clients (§5.1) — restyle plus the empty-ambiguity note.
			fmt.Print(view.Clients(rctx, sess.Clients, sess.EventsCount > 0))

			fmt.Print(view.SessionTags(rctx, sess.SessionTags))
			fmt.Print(view.DeniedEvents(rctx, sess.DeniedEventCount, sess.DeniedEventCounts))
			// Top Events / Resources Accessed now sort count-descending (§5).
			fmt.Print(view.TopEvents(rctx, sess.EventCounts))
			fmt.Print(view.ResourcesAccessed(rctx, sess.ResourcesAccessed))

			// AWS MCP Server agent traffic: show the MCP resource and the human session that
			// authorized the OAuth grant these agent credentials were minted under.
			if sess.AgentAuthorizedBySession != "" || sess.MCPResource != "" {
				if sess.MCPResource != "" {
					fmt.Fprintf(rctx.Out, "\n%s %s\n", rctx.Style(render.Header, "AWS MCP Server:"), rctx.Style(render.Ident, sess.MCPResource))
				}
				if sess.SignInSessionArn != "" {
					fmt.Fprintf(rctx.Out, "%s %s\n", rctx.Style(render.Header, "Sign-in session:"), rctx.Style(render.Ident, sess.SignInSessionArn))
				}
				if sess.AgentAuthorizedBySession != "" && sess.AgentAuthorizedBySession != sess.Ref() {
					printRefNav(ctx, rctx, s, "OAuth grant authorized by", sess.AgentAuthorizedBySession, label, now)
				}
			}

			// Login grant: show the human session that ran aws login to create these credentials
			if sess.LoginGrantedBySession != "" {
				fmt.Fprintln(rctx.Out)
				printRefNav(ctx, rctx, s, "Credentials granted via aws login by", sess.LoginGrantedBySession, label, now)
			}

			// Chaining: child view — show parent with navigable time
			if sess.AssumedFromSession != "" {
				fmt.Fprintln(rctx.Out)
				printRefNav(ctx, rctx, s, "Assumed by", sess.AssumedFromSession, label, now)
			}

			// Chaining: parent view — show each child session with navigable time
			if len(sess.ChainedSessionRefs) > 0 || len(sess.ChainedRoles) > 0 {
				fmt.Fprint(rctx.Out, rctx.Section(
					fmt.Sprintf("Assumed Roles (%d, %d events):", len(sess.ChainedRoles), sess.ChainedEventCount), ""))
				shown := 0
				for _, childRef := range sess.ChainedSessionRefs {
					childSess, _ := s.GetSessionByRef(ctx, CustomerID, childRef)
					if childSess == nil {
						fmt.Fprintf(rctx.Out, "  %s\n", childRef)
						continue
					}
					shown++
					printChildRow(rctx, childSess, childSess.RoleName, childRef, now)
				}
				if shown == 0 && len(sess.ChainedSessionRefs) == 0 {
					for _, childRoleARN := range sess.ChainedRoles {
						fmt.Fprintf(rctx.Out, "  %s\n", rctx.Style(render.Ident, childRoleARN))
					}
				}
			}

			// Grants: parent view — sessions whose credentials this session
			// authorized via aws login / MCP OAuth grants.
			if len(sess.GrantedSessionRefs) > 0 {
				fmt.Fprint(rctx.Out, rctx.Section(
					fmt.Sprintf("Authorized Sessions (%d):", len(sess.GrantedSessionRefs)), ""))
				for _, gRef := range sess.GrantedSessionRefs {
					gSess, _ := s.GetSessionByRef(ctx, CustomerID, gRef)
					if gSess == nil {
						fmt.Fprintf(rctx.Out, "  %s\n", gRef)
						continue
					}
					printChildRow(rctx, gSess, view.ShortRoleName(gSess.RoleName), gRef, now)
				}
			}

			fmt.Print(view.SessionPolicy(rctx, sess.SessionPolicy))

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
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
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
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
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
