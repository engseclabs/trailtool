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
		"accounts": accountsDetailCmd(),
		"roles":    rolesDetailCmd(),
		"services": servicesDetailCmd(),
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

func TestSessionSelector(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		user      string
		want      string
		wantError string
	}{
		{name: "positional SID", args: []string{"k7m2qp"}, want: "k7m2qp"},
		{name: "positional latest with user", args: []string{"latest"}, user: "alice@example.com", want: "latest"},
		{name: "missing", wantError: "required"},
		{name: "user with SID", args: []string{"k7m2qp"}, user: "alice@example.com", wantError: "only with latest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sessionSelector(tt.args, tt.user)
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
		})
	}
}
