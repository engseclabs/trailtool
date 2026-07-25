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

func TestSessionSelectorCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		legacyFlag string
		user       string
		want       string
		wantLegacy bool
		wantError  string
	}{
		{name: "positional SID", args: []string{"k7m2qp"}, want: "k7m2qp"},
		{name: "positional latest with user", args: []string{"latest"}, user: "alice@example.com", want: "latest"},
		{name: "legacy SID", legacyFlag: "k7m2qp", want: "k7m2qp", wantLegacy: true},
		{name: "missing", wantError: "required"},
		{name: "both", args: []string{"k7m2qp"}, legacyFlag: "latest", wantError: "mutually exclusive"},
		{name: "user with SID", args: []string{"k7m2qp"}, user: "alice@example.com", wantError: "only with latest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, usedLegacy, err := sessionSelector(tt.args, tt.legacyFlag, tt.user)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("sessionSelector() error = %v", err)
			}
			if got != tt.want || usedLegacy != tt.wantLegacy {
				t.Fatalf("sessionSelector() = %q/%t, want %q/%t", got, usedLegacy, tt.want, tt.wantLegacy)
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
			if cmd.Flag("session") == nil {
				t.Fatal("temporary --session compatibility flag is missing")
			}
		})
	}
}
