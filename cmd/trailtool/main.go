package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
			fmt.Fprintln(w, "EMAIL\tDISPLAY NAME\tSESSIONS\tROLES\tACCOUNTS\tLAST SEEN")
			for _, p := range people {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n",
					p.Email, p.DisplayName, p.SessionsCount, p.RolesCount, p.AccountsCount, p.LastSeen)
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
				return fatal("failed to connect to AWS: %v", err)
			}

			sessions, err := session.ListSessions(ctx, s, customerID, user, days)
			if err != nil {
				return fatal("%v", err)
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
	var startTime string

	cmd := &cobra.Command{
		Use:   "detail",
		Short: "Show session details",
		RunE: func(cmd *cobra.Command, args []string) error {
			if startTime == "" {
				return fatal("--start-time is required")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			sess, err := s.GetSession(ctx, customerID, startTime)
			if err != nil {
				return fatal("%v", err)
			}
			if sess == nil {
				return fatal("session not found")
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

	cmd.Flags().StringVar(&startTime, "start-time", "", "Session start time (ISO8601)")

	return cmd
}

func sessionsSummarizeCmd() *cobra.Command {
	var startTime string

	cmd := &cobra.Command{
		Use:   "summarize",
		Short: "Generate AI summary of a session via Bedrock",
		RunE: func(cmd *cobra.Command, args []string) error {
			if startTime == "" {
				return fatal("--start-time is required")
			}

			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			sess, err := s.GetSession(ctx, customerID, startTime)
			if err != nil {
				return fatal("%v", err)
			}
			if sess == nil {
				return fatal("session not found")
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

	cmd.Flags().StringVar(&startTime, "start-time", "", "Session start time (ISO8601)")

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
			fmt.Fprintln(w, "ACCOUNT ID\tNAME\tPEOPLE\tSESSIONS\tROLES\tSERVICES\tRESOURCES\tLAST SEEN")
			for _, a := range accounts {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
					a.AccountID, a.AccountName, a.PeopleCount, a.SessionsCount,
					a.RolesCount, a.ServicesCount, a.ResourcesCount, a.LastSeen)
			}
			return w.Flush()
		},
	}
}

func accountsDetailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detail [account-id]",
		Short: "Show account details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			account, err := s.GetAccount(ctx, customerID, args[0])
			if err != nil {
				return fatal("%v", err)
			}
			if account == nil {
				return fatal("account not found: %s", args[0])
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
			fmt.Fprintln(w, "NAME\tACCOUNT\tEVENTS\tPEOPLE\tSESSIONS\tDENIED\tLAST SEEN")
			for _, r := range roles {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
					r.Name, r.AccountID, r.TotalEvents, r.PeopleCount,
					r.SessionsCount, r.TotalDeniedEvents, r.LastSeen)
			}
			return w.Flush()
		},
	}
}

func rolesDetailCmd() *cobra.Command {
	var accountID string

	cmd := &cobra.Command{
		Use:   "detail [role-name-or-arn]",
		Short: "Show role details",
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
				for _, svc := range role.ServicesUsed {
					fmt.Printf("  %s\n", svc)
				}
			}

			if len(role.TopEventNames) > 0 {
				fmt.Println("\nTop Events:")
				for event, count := range role.TopEventNames {
					fmt.Printf("  %s: %d\n", event, count)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&accountID, "account", "", "Filter by AWS account ID (disambiguates roles with the same name)")

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
			fmt.Fprintln(w, "SERVICE\tDISPLAY NAME\tEVENTS\tROLES\tRESOURCES\tPEOPLE\tLAST SEEN")
			for _, svc := range services {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
					svc.EventSource, svc.DisplayName, svc.TotalEvents,
					svc.RolesCount, svc.ResourcesCount, svc.PeopleCount, svc.LastSeen)
			}
			return w.Flush()
		},
	}
}

func servicesDetailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detail [event-source]",
		Short: "Show service details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			s, err := store.NewStore(ctx)
			if err != nil {
				return fatal("failed to connect to AWS: %v", err)
			}

			svc, err := s.GetService(ctx, customerID, args[0])
			if err != nil {
				return fatal("%v", err)
			}
			if svc == nil {
				return fatal("service not found: %s", args[0])
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
				for event, count := range svc.TopEventNames {
					fmt.Printf("  %s: %d\n", event, count)
				}
			}

			return nil
		},
	}

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
				fmt.Fprintln(w, "RESOURCE\tTYPE\tACCOUNT\tCLICKOPS EVENTS\tLAST SEEN")
				for _, r := range resources {
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
						r.Name, r.Type, r.AccountID, r.ClickOpsCount, r.LastSeen)
				}
				w.Flush()

				fmt.Println("\n--- Console Operations ---")
				for _, r := range resources {
					fmt.Printf("\n%s (%s)\n", r.Name, r.Type)
					for _, access := range r.ClickOpsAccesses {
						date := access.AccessTime
						if len(date) >= 10 {
							date = date[:10]
						}
						fmt.Printf("  %s by %s (%dx) - %s\n",
							access.EventName, access.PersonEmail, access.EventCount, date)
					}
				}
			} else {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "RESOURCE\tTYPE\tACCOUNT\tEVENTS\tCLICKOPS\tLAST SEEN")
				for _, r := range resources {
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
						r.Name, r.Type, r.AccountID, r.TotalEvents, r.ClickOpsCount, r.LastSeen)
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
