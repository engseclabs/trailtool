package commands

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestDetailCommandsExposeDeniedDetailsFlag(t *testing.T) {
	commands := []struct {
		name string
		cmd  *cobra.Command
	}{
		{name: "accounts", cmd: accountsDetailCmd()},
		{name: "people", cmd: peopleDetailCmd()},
		{name: "resources", cmd: resourcesDetailCmd()},
		{name: "roles", cmd: rolesDetailCmd()},
		{name: "services", cmd: servicesDetailCmd()},
		{name: "sessions", cmd: sessionsDetailCmd()},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			flag := tc.cmd.Flags().Lookup("include-denied-details")
			if flag == nil {
				t.Fatal("missing --include-denied-details")
			}
			if flag.DefValue != "false" {
				t.Fatalf("default = %q, want false", flag.DefValue)
			}
			if tc.cmd.Flags().Lookup("include-denied") != nil {
				t.Fatal("detail command must not reuse policy-only --include-denied")
			}
		})
	}
}

func TestSessionDetailExposesVerboseFlag(t *testing.T) {
	flag := sessionsDetailCmd().Flags().Lookup("verbose")
	if flag == nil {
		t.Fatal("missing --verbose")
	}
	if flag.DefValue != "false" {
		t.Fatalf("default = %q, want false", flag.DefValue)
	}
}
