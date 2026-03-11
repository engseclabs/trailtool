package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/policy"
	"github.com/engseclabs/trailtool/core/session"
	"github.com/engseclabs/trailtool/core/store"
)

var customerID = "default"

func init() {
	if id := os.Getenv("TRAILTOOL_CUSTOMER_ID"); id != "" {
		customerID = id
	}
}

var format string

func main() {
	rootCmd := &cobra.Command{
		Use:   "trailtool",
		Short: "TrailTool - AWS CloudTrail analysis CLI",
		Long:  "Analyze AWS CloudTrail data for user sessions, role usage, and IAM policy generation.",
	}

	rootCmd.PersistentFlags().StringVar(&format, "format", "text", "Output format: text or json")

	rootCmd.AddCommand(usersCmd())
	rootCmd.AddCommand(policyCmd())
	rootCmd.AddCommand(sessionsCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- users ---

func usersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage users",
	}
	cmd.AddCommand(usersListCmd())
	return cmd
}

func usersListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tracked users",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to connect to AWS: %v\n", err)
				os.Exit(1)
				return nil
			}

			people, err := s.ListPeople(ctx, customerID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
				return nil
			}

			if format == "json" {
				return printJSON(people)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "EMAIL\tDISPLAY NAME\tSESSIONS\tROLES\tACCOUNTS\tLAST SEEN")
			for _, p := range people {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n",
					p.Email, p.DisplayName, p.SessionsCount, p.RolesCount, p.AccountsCount, p.LastSeen)
			}
			return w.Flush()
		},
	}
}

// --- policy ---

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "IAM policy operations",
	}
	cmd.AddCommand(policyGenerateCmd())
	return cmd
}

func policyGenerateCmd() *cobra.Command {
	var roleName string
	var days int
	var includeDenied bool
	var explain bool

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate least-privilege IAM policy for a role",
		RunE: func(cmd *cobra.Command, args []string) error {
			if roleName == "" {
				fmt.Fprintln(os.Stderr, "Error: --role is required")
				os.Exit(3)
				return nil
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to connect to AWS: %v\n", err)
				os.Exit(1)
				return nil
			}

			// Try as ARN first, then by name
			var role *models.Role
			if len(roleName) >= 3 && roleName[:3] == "arn" {
				role, err = s.GetRole(ctx, customerID, roleName)
			} else {
				role, err = s.GetRoleByName(ctx, customerID, roleName)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
				return nil
			}
			if role == nil {
				fmt.Fprintf(os.Stderr, "Error: role not found: %s\n", roleName)
				os.Exit(2)
				return nil
			}

			result, err := policy.GeneratePolicy(role, includeDenied)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
				return nil
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

	cmd.Flags().StringVar(&roleName, "role", "", "Role name or ARN")
	cmd.Flags().IntVar(&days, "days", 0, "Filter to last N days of activity")
	cmd.Flags().BoolVar(&includeDenied, "include-denied", false, "Include denied events in policy")
	cmd.Flags().BoolVar(&explain, "explain", false, "Show policy explanation on stderr")

	return cmd
}

// --- sessions ---

func sessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Session operations",
	}
	cmd.AddCommand(sessionsListCmd())
	cmd.AddCommand(sessionsDetailCmd())
	cmd.AddCommand(sessionsSummarizeCmd())
	return cmd
}

func sessionsListCmd() *cobra.Command {
	var user string
	var days int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to connect to AWS: %v\n", err)
				os.Exit(1)
				return nil
			}

			sessions, err := session.ListSessions(ctx, s, customerID, user, days)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
				return nil
			}

			if format == "json" {
				return printJSON(sessions)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "START TIME\tUSER\tROLE\tACCOUNT\tEVENTS\tTYPE\tDURATION")
			for _, sess := range sessions {
				sessionType := sess.DetectSessionType()
				duration := fmt.Sprintf("%dm", sess.DurationMinutes)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
					sess.StartTime, sess.PersonEmail, sess.RoleName, sess.AccountID,
					sess.EventsCount, sessionType, duration)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "Filter by user email")
	cmd.Flags().IntVar(&days, "days", 0, "Filter to last N days")

	return cmd
}

func sessionsDetailCmd() *cobra.Command {
	var sessionID string
	var startTime string

	cmd := &cobra.Command{
		Use:   "detail",
		Short: "Show session details",
		RunE: func(cmd *cobra.Command, args []string) error {
			if startTime == "" {
				fmt.Fprintln(os.Stderr, "Error: --start-time is required")
				os.Exit(3)
				return nil
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to connect to AWS: %v\n", err)
				os.Exit(1)
				return nil
			}

			sess, err := s.GetSession(ctx, customerID, startTime)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
				return nil
			}
			if sess == nil {
				fmt.Fprintln(os.Stderr, "Error: session not found")
				os.Exit(2)
				return nil
			}

			if format == "json" {
				return printJSON(sess)
			}

			fmt.Printf("Session: %s\n", sess.SessionID)
			fmt.Printf("User: %s\n", sess.PersonEmail)
			fmt.Printf("Role: %s (%s)\n", sess.RoleName, sess.RoleARN)
			fmt.Printf("Account: %s\n", sess.AccountID)
			fmt.Printf("Type: %s\n", sess.DetectSessionType())
			fmt.Printf("Time: %s -> %s (%dm)\n", sess.StartTime, sess.EndTime, sess.DurationMinutes)
			fmt.Printf("Events: %d across %d services\n", sess.EventsCount, sess.ServicesCount)

			if sess.DeniedEventCount > 0 {
				fmt.Printf("Denied Events: %d\n", sess.DeniedEventCount)
			}

			fmt.Println("\nTop Events:")
			for event, count := range sess.EventCounts {
				fmt.Printf("  %s: %d\n", event, count)
			}

			if len(sess.ResourcesAccessed) > 0 {
				fmt.Println("\nResources Accessed:")
				for resource, count := range sess.ResourcesAccessed {
					fmt.Printf("  %s: %d\n", resource, count)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session-id", "", "Session ID")
	cmd.Flags().StringVar(&startTime, "start-time", "", "Session start time (ISO8601)")

	return cmd
}

func sessionsSummarizeCmd() *cobra.Command {
	var sessionID string
	var startTime string

	cmd := &cobra.Command{
		Use:   "summarize",
		Short: "Generate AI summary of a session via Bedrock",
		RunE: func(cmd *cobra.Command, args []string) error {
			if startTime == "" {
				fmt.Fprintln(os.Stderr, "Error: --start-time is required")
				os.Exit(3)
				return nil
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to connect to AWS: %v\n", err)
				os.Exit(1)
				return nil
			}

			sess, err := s.GetSession(ctx, customerID, startTime)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
				return nil
			}
			if sess == nil {
				fmt.Fprintln(os.Stderr, "Error: session not found")
				os.Exit(2)
				return nil
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
				fmt.Fprintf(os.Stderr, "Error: bedrock invocation failed: %v\n", err)
				os.Exit(4)
				return nil
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

	cmd.Flags().StringVar(&sessionID, "session-id", "", "Session ID")
	cmd.Flags().StringVar(&startTime, "start-time", "", "Session start time (ISO8601)")

	return cmd
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
