package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/view"
	"github.com/engseclabs/trailtool/core/models"
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
	var verbose bool

	cmd := &cobra.Command{
		Use:   "detail [sid-or-latest]",
		Short: "Show session details",
		Long: `Show details for a session identified by its id (the SID column from
'trailtool sessions list'). A short prefix is enough; "latest" jumps to the
most recent session.

Examples:
  trailtool sessions detail k7m2qp
  trailtool sessions detail latest
  trailtool sessions detail k7m2qp --verbose`,
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
			label := personLabels(ctx, s)

			timeLine := fmt.Sprintf("%s (%dm)",
				rctx.Interval(sess.StartTime, sess.EndTime), sess.DurationMinutes)
			origin := loadSessionOrigin(ctx, s, sess, label)
			lineageRows, omittedLineage := loadSessionLineage(ctx, s, sess, label, relationLimit)

			fmt.Print(view.SessionOverview(rctx, sess, label(sess.PersonKey), timeLine, verbose))
			fmt.Print(view.SessionOrigin(rctx, sess, origin, verbose))
			fmt.Print(view.SessionSummary(rctx, sess))
			if verbose {
				fmt.Print(view.VerboseClients(rctx, sess.Clients, sess.EventsCount > 0))
			} else {
				fmt.Print(view.Clients(rctx, sess.Clients, sess.EventsCount > 0))
			}
			fmt.Print(view.TopEvents(rctx, sess.EventCounts))
			fmt.Print(view.SessionResourceActivity(rctx, sess.ResourceAccesses))
			fmt.Print(view.SessionClickOps(rctx, sess.ClickOpsEventCount, sess.ClickOpsEventCounts))
			if includeDeniedDetails {
				deniedDetails := view.SessionDeniedActivity(rctx, sess.DeniedResourceAccesses, sess.DeniedEventAccesses)
				if deniedDetails == "" {
					deniedDetails = view.DeniedEvents(rctx, sess.DeniedEventCount, sess.DeniedEventCounts)
				}
				fmt.Print(deniedDetails)
			}
			fmt.Print(view.SessionRelationships(rctx, &detail))
			fmt.Print(view.SessionLineage(rctx, lineageRows, omittedLineage))
			if verbose {
				fmt.Print(view.SessionPolicy(rctx, sess.SessionPolicy))
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", defaultDetailLimit, "Maximum rows in each related section")
	cmd.Flags().BoolVar(&all, "all", false, "Show every related record")
	cmd.Flags().BoolVar(&includeDeniedDetails, "include-denied-details", false, "Show denied event breakdowns and access details")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show internal identifiers, full client metadata, and raw session policy")

	return cmd
}

func loadSessionOrigin(
	ctx context.Context,
	s *store.Store,
	sess *models.Session,
	label func(string) string,
) view.SessionOriginReference {
	ref := ""
	switch {
	case sess.AgentAuthorizedBySession != "":
		ref = sess.AgentAuthorizedBySession
	case sess.LoginGrantedBySession != "":
		ref = sess.LoginGrantedBySession
	case sess.AssumedFromSession != "":
		ref = sess.AssumedFromSession
	}
	if ref == "" || ref == sess.Ref() {
		return view.SessionOriginReference{}
	}
	parent, _ := s.GetSessionByRef(ctx, CustomerID, ref)
	return view.SessionOriginReference{
		Ref:         ref,
		PersonLabel: label(view.RefPersonKey(ref)),
		Session:     parent,
	}
}

func loadSessionLineage(
	ctx context.Context,
	s *store.Store,
	sess *models.Session,
	label func(string) string,
	limit int,
) ([]view.SessionLineageRow, int) {
	var rows []view.SessionLineageRow
	omitted := 0
	capRefs := func(refs []string) []string {
		if limit == 0 {
			return refs
		}
		remaining := max(limit-len(rows), 0)
		if len(refs) <= remaining {
			return refs
		}
		omitted += len(refs) - remaining
		return refs[:remaining]
	}
	appendRefs := func(relation string, refs []string) {
		for _, ref := range capRefs(refs) {
			target, _ := s.GetSessionByRef(ctx, CustomerID, ref)
			rows = append(rows, view.SessionLineageRow{
				Relation:    relation,
				Ref:         ref,
				PersonLabel: label(view.RefPersonKey(ref)),
				Session:     target,
			})
		}
	}

	appendRefs("assumed", sess.ChainedSessionRefs)
	if len(sess.ChainedSessionRefs) == 0 {
		for _, roleARN := range capRefs(sess.ChainedRoles) {
			role := roleARN
			if slash := strings.LastIndexByte(roleARN, '/'); slash != -1 && slash+1 < len(roleARN) {
				role = roleARN[slash+1:]
			}
			rows = append(rows, view.SessionLineageRow{Relation: "assumed", Role: role})
		}
	}
	appendRefs("authorized", sess.GrantedSessionRefs)
	return rows, omitted
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
