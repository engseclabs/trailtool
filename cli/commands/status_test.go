package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestStatusJSONUsesStableChecksWithoutAWS(t *testing.T) {
	oldFormat := Format
	Format = "json"
	t.Cleanup(func() { Format = oldFormat })

	checks := []StatusCheck{
		newStatusCheck("aws_credentials", "ok", "Authenticated"),
		newStatusCheck("ingestor_stack", "warn", "Not found", "checked three names"),
		newStatusCheck("data_access", "fail", "Query failed", "denied"),
	}
	called := false
	exitCode := 0
	cmd := statusCmd(
		func(context.Context) []StatusCheck {
			called = true
			return checks
		},
		func(code int) { exitCode = code },
	)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("status command error = %v", err)
	}
	if !called {
		t.Fatal("injected status checker was not called")
	}
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if stderr.Len() != 0 {
		t.Fatalf("JSON wrote stderr: %q", stderr.String())
	}

	var got []StatusCheck
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if len(got) != 3 {
		t.Fatalf("checks = %#v", got)
	}
	for i := range got {
		if got[i].Check != checks[i].Check ||
			got[i].Status != checks[i].Status ||
			got[i].Message == "" ||
			got[i].Diagnostics == nil {
			t.Fatalf("check %d = %#v", i, got[i])
		}
	}
}

func TestStatusTextKeepsDiagnosticsOnStderr(t *testing.T) {
	oldFormat, oldColor := Format, ColorMode
	Format, ColorMode = "text", "never"
	t.Cleanup(func() {
		Format, ColorMode = oldFormat, oldColor
	})

	cmd := statusCmd(
		func(context.Context) []StatusCheck {
			return []StatusCheck{
				newStatusCheck("aws_credentials", "fail", "Could not authenticate", "credential expired"),
			}
		},
		func(int) {},
	)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status command error = %v", err)
	}
	if !strings.Contains(stdout.String(), "AWS credentials: FAIL\n") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "  Could not authenticate\n  credential expired\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
