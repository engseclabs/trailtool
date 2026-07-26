package commands

import (
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/spf13/cobra"
)

func TestIndexFlagsAreRemoved(t *testing.T) {
	tests := map[string]*cobra.Command{
		"accounts detail": accountsDetailCmd(),
		"roles detail":    rolesDetailCmd(),
		"services detail": servicesDetailCmd(),
	}
	for name, cmd := range tests {
		t.Run(name, func(t *testing.T) {
			if flag := cmd.Flag("index"); flag != nil {
				t.Fatalf("--index still registered: %#v", flag)
			}
			if err := cmd.ParseFlags([]string{"--index", "1"}); err == nil ||
				!strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("parsing --index returned %v, want unknown flag", err)
			}
		})
	}
}

func TestCanonicalDetailCommandsRequireOneSelector(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"accounts":  accountsDetailCmd(),
		"people":    peopleDetailCmd(),
		"resources": resourcesDetailCmd(),
		"roles":     rolesDetailCmd(),
		"services":  servicesDetailCmd(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Args(cmd, nil); err == nil {
				t.Fatal("missing selector was accepted")
			}
			if err := cmd.Args(cmd, []string{"one"}); err != nil {
				t.Fatalf("one selector rejected: %v", err)
			}
			if err := cmd.Args(cmd, []string{"one", "two"}); err == nil {
				t.Fatal("multiple selectors were accepted")
			}
		})
	}
}

func TestPIDAndRIDMatchResolution(t *testing.T) {
	people := []models.Person{
		{Pid: "abcdef1", PersonKey: "email#one@example.com"},
		{Pid: "abcdef2", PersonKey: "email#two@example.com"},
	}
	if _, err := resolvePersonMatches("missing", nil); err == nil || !strings.Contains(err.Error(), "people list") {
		t.Fatalf("person no-match error = %v", err)
	}
	if got, err := resolvePersonMatches("abcdef1", people[:1]); err != nil || got.PersonKey != people[0].PersonKey {
		t.Fatalf("person unique match = %#v, %v", got, err)
	}
	if _, err := resolvePersonMatches("abcdef", people); err == nil ||
		!strings.Contains(err.Error(), "abcdef1") ||
		!strings.Contains(err.Error(), "abcdef2") {
		t.Fatalf("person ambiguous error = %v", err)
	}

	resources := []models.Resource{
		{Rid: "uvwxyz1", AccountID: "111", Identifier: "lambda:function:worker"},
		{Rid: "uvwxyz2", AccountID: "222", Identifier: "lambda:function:worker"},
	}
	if _, err := resolveResourceMatches("missing", nil); err == nil || !strings.Contains(err.Error(), "resources list") {
		t.Fatalf("resource no-match error = %v", err)
	}
	if got, err := resolveResourceMatches("uvwxyz1", resources[:1]); err != nil || got.AccountID != "111" {
		t.Fatalf("resource unique match = %#v, %v", got, err)
	}
	if _, err := resolveResourceMatches("uvwxyz", resources); err == nil ||
		!strings.Contains(err.Error(), "uvwxyz1") ||
		!strings.Contains(err.Error(), "uvwxyz2") {
		t.Fatalf("resource ambiguous error = %v", err)
	}
}

func TestDetailRelationLimitFlags(t *testing.T) {
	cmd := peopleDetailCmd()
	if got, err := detailRelationLimit(cmd, defaultDetailLimit, false); err != nil || got != defaultDetailLimit {
		t.Fatalf("default limit = %d, %v", got, err)
	}
	if got, err := detailRelationLimit(cmd, defaultDetailLimit, true); err != nil || got != 0 {
		t.Fatalf("--all limit = %d, %v", got, err)
	}
	if _, err := detailRelationLimit(cmd, 0, false); err == nil || !strings.Contains(err.Error(), "at least 1") {
		t.Fatalf("zero limit error = %v", err)
	}

	cmd = resourcesDetailCmd()
	if err := cmd.Flags().Set("limit", "3"); err != nil {
		t.Fatal(err)
	}
	if _, err := detailRelationLimit(cmd, 3, true); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("combined flags error = %v", err)
	}

	for name, detailCmd := range map[string]*cobra.Command{
		"account":  accountsDetailCmd(),
		"person":   peopleDetailCmd(),
		"resource": resourcesDetailCmd(),
		"role":     rolesDetailCmd(),
		"service":  servicesDetailCmd(),
		"session":  sessionsDetailCmd(),
	} {
		t.Run(name, func(t *testing.T) {
			if detailCmd.Flag("limit") == nil || detailCmd.Flag("all") == nil {
				t.Fatalf("detail command flags = %#v", detailCmd.Flags())
			}
		})
	}
}

func TestSessionSelector(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		want      string
		wantError string
	}{
		{name: "positional SID", args: []string{"k7m2qp"}, want: "k7m2qp"},
		{name: "positional latest", args: []string{"latest"}, want: "latest"},
		{name: "missing", wantError: "required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sessionSelector(tt.args)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("sessionSelector() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("sessionSelector() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoleIDMatchResolution(t *testing.T) {
	roles := []models.Role{
		{RoleSelector: "abcdef1aaaaaaaaa", AccountID: "111", ARN: "arn:aws:iam::111:role/Admin"},
		{RoleSelector: "abcdef2bbbbbbbbb", AccountID: "222", ARN: "arn:aws:iam::222:role/Admin"},
	}
	if got, err := resolveRoleIDMatches("missing", nil); err != nil || got != nil {
		t.Fatalf("missing role match = %#v, %v", got, err)
	}
	if got, err := resolveRoleIDMatches("abcdef1", roles[:1]); err != nil || got == nil || got.AccountID != "111" {
		t.Fatalf("unique role match = %#v, %v", got, err)
	}
	if _, err := resolveRoleIDMatches("abcdef", roles); err == nil ||
		!strings.Contains(err.Error(), "abcdef1") ||
		!strings.Contains(err.Error(), "abcdef2") {
		t.Fatalf("ambiguous role error = %v", err)
	}
}

func TestRoleCommandsUseRoleID(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"detail": rolesDetailCmd(),
		"policy": rolesPolicyCmd(),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(cmd.Use, "<role-id>") {
				t.Fatalf("Use = %q, want role ID selector", cmd.Use)
			}
			if !strings.Contains(cmd.Long, "full role ARN") || !strings.Contains(cmd.Long, "exact role name") {
				t.Fatalf("fallback selectors missing from help: %q", cmd.Long)
			}
		})
	}
}

func TestSessionCommandsAcceptOnePositionalSelector(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"detail":    sessionsDetailCmd(),
		"summarize": sessionsSummarizeCmd(),
		"policy":    sessionsPolicyCmd(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := cmd.Args(cmd, []string{"k7m2qp"}); err != nil {
				t.Fatalf("positional selector rejected: %v", err)
			}
			if err := cmd.Args(cmd, []string{"one", "two"}); err == nil {
				t.Fatal("multiple selectors were accepted")
			}
			if cmd.Flag("session") != nil {
				t.Fatal("removed --session flag is still registered")
			}
			if cmd.Flag("user") != nil {
				t.Fatal("--user belongs only on sessions list")
			}
			if name == "summarize" && cmd.Flag("refresh") == nil {
				t.Fatal("summarize --refresh flag is missing")
			}
		})
	}
}

func TestLatestSessionUsesStartTimeThenSID(t *testing.T) {
	sessions := []models.Session{
		{Sid: "z", StartTime: "2025-01-01T00:00:00Z"},
		{Sid: "a", StartTime: "2026-07-24T12:00:00Z"},
		{Sid: "b", StartTime: "2026-07-24T12:00:00Z"},
	}
	got, err := latestSession(sessions)
	if err != nil {
		t.Fatalf("latestSession() error = %v", err)
	}
	if got.Sid != "b" {
		t.Fatalf("latest SID = %q, want b", got.Sid)
	}
}
