package commands

import (
	"strings"
	"testing"

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
