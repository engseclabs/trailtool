package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
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
	var sessionType string
	var hasDenied bool
	var tags []string
	var long bool
	var reverse bool
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			filter := store.SessionFilter{
				Days:        days,
				AccountID:   account,
				After:       after,
				Before:      before,
				SessionType: sessionType,
				HasDenied:   hasDenied,
			}
			if err := filter.Validate(); err != nil {
				return fatal("%v", err)
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			var roleARN string
			if role != "" {
				resolvedRole, resolveErr := lookupRole(ctx, s, role, account)
				if resolveErr != nil {
					return fatal("%v", resolveErr)
				}
				if resolvedRole == nil {
					return fatal("role not found: %s (check 'trailtool roles list')", role)
				}
				roleARN = resolvedRole.ARN
			}
			filter.RoleARN = roleARN
			// Let the store's recency Query stop after `limit` newest rows on the
			// cross-everyone path. Tag filtering happens client-side below, so when
			// --tag is set we can't bound server-side without under-fetching; fall
			// back to no server limit and let the client-side cap apply.
			if len(tags) == 0 {
				filter.Limit = limit
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

			// Default newest-first; --reverse shows oldest-first. Sort before
			// capping so --limit keeps the intended slice (the most recent N),
			// not an arbitrary prefix.
			models.SortSessionsForList(sessions, !reverse)
			sessions = capList(sessions, limit)

			if Format == "json" {
				return printJSON(sessions)
			}

			label := personLabels(ctx, s)
			sidWidth := view.SidDisplayWidth(sessions)
			rctx := renderContext()
			fmt.Print(view.SessionList(rctx, sessions, sidWidth, long, label))
			return nil
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "Filter by user email, PID, or person key")
	cmd.Flags().IntVar(&days, "days", 0, "Filter to last N days")
	cmd.Flags().StringVar(&role, "role", "", "Filter by role ID, ARN, or exact name")
	cmd.Flags().StringVar(&account, "account", "", "Filter by AWS account ID")
	cmd.Flags().StringVar(&after, "after", "", "Only sessions starting at or after this time (RFC3339)")
	cmd.Flags().StringVar(&before, "before", "", "Only sessions starting before this time (RFC3339)")
	cmd.Flags().StringVar(&sessionType, "type", "", "Filter by session type: cli, web, agent, or login")
	cmd.Flags().BoolVar(&hasDenied, "has-denied", false, "Only show sessions with denied activity")
	cmd.Flags().StringArrayVar(&tags, "tag", nil, "Filter by session tag KEY=VALUE (repeatable, AND semantics)")
	cmd.Flags().BoolVar(&long, "long", false, "Show full role names instead of shortened SSO permission-set names")
	cmd.Flags().BoolVar(&reverse, "reverse", false, "Show oldest sessions first (default is newest first)")
	addListLimitFlag(cmd, &limit)

	return cmd
}

func sessionsDetailCmd() *cobra.Command {
	var limit int
	var all bool
	var includeDeniedDetails bool

	cmd := &cobra.Command{
		Use:   "detail [sid-or-latest]",
		Short: "Show session details",
		Long: `Show details for a session identified by its id (the SID column from
'trailtool sessions list'). A short prefix is enough; "latest" jumps to the
most recent session.

Examples:
  trailtool sessions detail k7m2qp
  trailtool sessions detail latest`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			selector, selectErr := sessionSelector(args)
			if selectErr != nil {
				return fatal("%v", selectErr)
			}
			relationLimit, limitErr := detailRelationLimit(cmd, limit, all)
			if limitErr != nil {
				return fatal("%v", limitErr)
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			sess, err := resolveSession(ctx, s, selector)
			if err != nil {
				return fatal("%v", err)
			}

			related, err := s.LoadRelatedNouns(
				ctx,
				CustomerID,
				store.RelationKindSession,
				sess.Ref(),
				relationLimit,
			)
			if err != nil {
				return fatal("%v", err)
			}
			sess.ApplyRelationshipCounts(related.Counts)
			detail := models.SessionDetail{Session: *sess, Related: related}

			if Format == "json" {
				return printJSON(detail)
			}

			rctx := renderContext()
			now := rctx.Now
			label := personLabels(ctx, s)

			// Title + key facts (§5). The time line uses the render context's
			// centralized clock and interval rule (§4.5).
			timeLine := fmt.Sprintf("%s (%dm)",
				rctx.Interval(sess.StartTime, sess.EndTime), sess.DurationMinutes)
			fmt.Print(view.SessionTitleKV(rctx, sess, label(sess.PersonKey), timeLine))

			// Clients (§5.1) — restyle plus the empty-ambiguity note.
			fmt.Print(view.Clients(rctx, sess.Clients, sess.EventsCount > 0))

			fmt.Print(view.SessionTags(rctx, sess.SessionTags))
			if includeDeniedDetails {
				fmt.Print(view.DeniedEvents(rctx, sess.DeniedEventCount, sess.DeniedEventCounts))
			}
			fmt.Print(view.SessionClickOps(rctx, sess.ClickOpsEventCount, sess.ClickOpsEventCounts))
			// Top Events sort count-descending (§5).
			fmt.Print(view.TopEvents(rctx, sess.EventCounts))
			fmt.Print(view.SessionResourceActivity(rctx, sess.ResourceAccesses))
			if includeDeniedDetails {
				fmt.Print(view.SessionDeniedActivity(rctx, sess.DeniedResourceAccesses, sess.DeniedEventAccesses))
			}
			fmt.Print(view.SessionSummary(rctx, sess))
			fmt.Print(view.SessionRelationships(rctx, &detail))

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

			// Chaining: parent view — show each child session with navigable time.
			// Capped to relationLimit refs (each is a sequential GetSessionByRef);
			// a session that assumed hundreds of roles would otherwise fan out into
			// hundreds of round-trips before rendering. --all (relationLimit 0) shows
			// every ref.
			if len(sess.ChainedSessionRefs) > 0 || len(sess.ChainedRoles) > 0 {
				fmt.Fprint(rctx.Out, rctx.Section(
					fmt.Sprintf("Assumed Roles (%d, %d events):", len(sess.ChainedRoles), sess.ChainedEventCount), ""))
				shown := 0
				childRefs := capList(sess.ChainedSessionRefs, relationLimit)
				for _, childRef := range childRefs {
					childSess, _ := s.GetSessionByRef(ctx, CustomerID, childRef)
					if childSess == nil {
						fmt.Fprintf(rctx.Out, "  %s\n", childRef)
						continue
					}
					shown++
					printChildRow(rctx, childSess, childSess.RoleName, childRef, now)
				}
				printMoreRefs(rctx, len(sess.ChainedSessionRefs)-len(childRefs))
				if shown == 0 && len(sess.ChainedSessionRefs) == 0 {
					for _, childRoleARN := range sess.ChainedRoles {
						fmt.Fprintf(rctx.Out, "  %s\n", rctx.Style(render.Ident, childRoleARN))
					}
				}
			}

			// Grants: parent view — sessions whose credentials this session
			// authorized via aws login / MCP OAuth grants. Same per-ref
			// GetSessionByRef cost, capped the same way.
			if len(sess.GrantedSessionRefs) > 0 {
				fmt.Fprint(rctx.Out, rctx.Section(
					fmt.Sprintf("Authorized Sessions (%d):", len(sess.GrantedSessionRefs)), ""))
				grantRefs := capList(sess.GrantedSessionRefs, relationLimit)
				for _, gRef := range grantRefs {
					gSess, _ := s.GetSessionByRef(ctx, CustomerID, gRef)
					if gSess == nil {
						fmt.Fprintf(rctx.Out, "  %s\n", gRef)
						continue
					}
					printChildRow(rctx, gSess, view.ShortRoleName(gSess.RoleName), gRef, now)
				}
				printMoreRefs(rctx, len(sess.GrantedSessionRefs)-len(grantRefs))
			}

			fmt.Print(view.SessionPolicy(rctx, sess.SessionPolicy))

			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", defaultDetailLimit, "Maximum rows in each related section")
	cmd.Flags().BoolVar(&all, "all", false, "Show every related record")
	cmd.Flags().BoolVar(&includeDeniedDetails, "include-denied-details", false, "Show denied event breakdowns and access details")

	return cmd
}

func sessionsSummarizeCmd() *cobra.Command {
	var refresh bool

	cmd := &cobra.Command{
		Use:   "summarize [sid-or-latest]",
		Short: "Generate AI summary of a session via Bedrock",
		Long: `Generate an AI summary of a session identified by its id (the SID column
from 'trailtool sessions list'). A short prefix is enough; "latest" jumps to
the most recent session.

Examples:
  trailtool sessions summarize k7m2qp
  trailtool sessions summarize latest`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			selector, selectErr := sessionSelector(args)
			if selectErr != nil {
				return fatal("%v", selectErr)
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			sess, err := resolveSession(ctx, s, selector)
			if err != nil {
				return fatal("%v", err)
			}

			if !refresh && session.SummaryIsCurrent(sess) {
				if Format == "json" {
					return printJSON(summaryOutput(sess, true))
				}
				fmt.Println(sess.Summary)
				return nil
			}

			result, err := session.SummarizeSession(ctx, sess)
			if err != nil {
				return fatal("%v", err)
			}
			sess.Summary = result.Summary
			sess.SummaryGeneratedAt = result.GeneratedAt
			sess.SummaryModel = result.Model
			sess.SummaryTokensUsed = result.TokensUsed
			sess.SummaryInputDigest = result.InputDigest

			if err := s.SaveSessionSummary(ctx, CustomerID, sess); err != nil {
				return fatal("could not save session summary: %v", err)
			}
			if Format == "json" {
				return printJSON(summaryOutput(sess, false))
			}
			fmt.Println(sess.Summary)
			return nil
		},
	}

	cmd.Flags().BoolVar(&refresh, "refresh", false, "Generate a new summary even when the cached summary is current")

	return cmd
}

type sessionSummaryOutput struct {
	Summary            string `json:"summary"`
	GeneratedAt        string `json:"generated_at"`
	Model              string `json:"model"`
	TokensUsed         int    `json:"tokens_used"`
	SummaryInputDigest string `json:"summary_input_digest"`
	Cached             bool   `json:"cached"`
}

func summaryOutput(sess *models.Session, cached bool) sessionSummaryOutput {
	return sessionSummaryOutput{
		Summary:            sess.Summary,
		GeneratedAt:        sess.SummaryGeneratedAt,
		Model:              sess.SummaryModel,
		TokensUsed:         sess.SummaryTokensUsed,
		SummaryInputDigest: sess.SummaryInputDigest,
		Cached:             cached,
	}
}

func sessionsPolicyCmd() *cobra.Command {
	var includeDenied bool
	var explain bool

	cmd := &cobra.Command{
		Use:   "policy [sid-or-latest]",
		Short: "Generate least-privilege IAM policy for a session",
		Long: `Generate a least-privilege IAM policy scoped to a specific session,
identified by its id (the SID column from 'trailtool sessions list'). A short
prefix is enough; "latest" jumps to the most recent session.

Examples:
  trailtool sessions policy k7m2qp
  trailtool sessions policy latest
  trailtool sessions policy k7m2qp --include-denied --explain`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			selector, selectErr := sessionSelector(args)
			if selectErr != nil {
				return fatal("%v", selectErr)
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatalAWS("Check AWS credentials and region (AWS_PROFILE, AWS_REGION), then re-run.", err)
			}

			sess, err := resolveSession(ctx, s, selector)
			if err != nil {
				return fatal("%v", err)
			}

			result, err := policy.GeneratePolicyFromSession(sess, includeDenied)
			if err != nil {
				return fatal("%v", err)
			}

			if Format == "json" {
				if err := printJSON(result); err != nil {
					return err
				}
			} else {
				fmt.Println(result.PolicyJSON)
			}

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

	cmd.Flags().BoolVar(&includeDenied, "include-denied", false, "Include denied events in policy")
	cmd.Flags().BoolVar(&explain, "explain", false, "Show policy explanation on stderr")

	return cmd
}

func sessionSelector(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("session id argument is required (for example, k7m2qp or latest)")
	}
	return args[0], nil
}
