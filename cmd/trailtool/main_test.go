package main

import (
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/cli/commands"
)

func TestRootRejectsInvalidGlobalFlagsBeforeRunningCommand(t *testing.T) {
	oldFormat, oldColor := commands.Format, commands.ColorMode
	t.Cleanup(func() {
		commands.Format, commands.ColorMode = oldFormat, oldColor
	})

	tests := []struct {
		name      string
		args      []string
		wantError string
	}{
		{name: "format", args: []string{"--format", "yaml", "status"}, wantError: "invalid --format"},
		{name: "color", args: []string{"--color", "sometimes", "status"}, wantError: "invalid --color"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tt.args)
			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Execute() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}
