package view

import (
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

func oneClient() []models.ClientAggregate {
	return []models.ClientAggregate{{
		Key: "aws-cli", Name: "aws-cli", Version: "2.15.0", Category: "cli",
		OS: "macos", OSVersion: "14.2", Architecture: "arm64", Runtime: "python 3.11",
		TotalEventCount: 30, DeniedEventCount: 0,
		FirstSeen: "2026-07-24T09:00:00Z", LastSeen: "2026-07-24T09:45:00Z",
		Commands: map[string]int{"s3:GetObject": 20, "s3:ListBucket": 10, "ua:s3.cp": 5},
	}}
}

func mixedFamilies() []models.ClientAggregate {
	return []models.ClientAggregate{
		{
			Key: "aws-cli", Name: "aws-cli", Version: "2.15.0", Category: "cli",
			OS: "linux", Architecture: "x86_64",
			TotalEventCount: 50, DeniedEventCount: 4, ServiceDrivenEventCount: 2,
			FirstSeen: "2026-07-24T08:00:00Z", LastSeen: "2026-07-24T10:00:00Z",
			Commands: map[string]int{
				"ec2:DescribeInstances": 30,
				"ec2:RunInstances":      20,
				"ua:lambda.update":      3,
			},
		},
		{
			Key: "Boto3", Name: "Boto3", Version: "1.34.0", Category: "sdk",
			OS: "linux", Runtime: "python 3.12",
			TotalEventCount: 12, DeniedEventCount: 0,
			FirstSeen: "2026-07-24T08:30:00Z", LastSeen: "2026-07-24T09:00:00Z",
			Commands: map[string]int{"dynamodb:Query": 12},
		},
	}
}

func TestGoldenClients(t *testing.T) {
	// One client, denied/service-driven activity, mixed families, and the two
	// ambiguity cases (absent clients with/without events) — the §9 fixture set.
	assertGolden(t, "clients_one_plain", Clients(ctxFor(100, false, true), oneClient(), true))
	assertGolden(t, "clients_one_color", Clients(ctxFor(100, true, true), oneClient(), true))
	assertGolden(t, "clients_mixed_plain", Clients(ctxFor(100, false, true), mixedFamilies(), true))
	assertGolden(t, "clients_mixed_ascii", Clients(ctxFor(100, false, false), mixedFamilies(), true))

	// Absent clients but the session had events → ambiguity note.
	assertGolden(t, "clients_absent_note", Clients(ctxFor(80, false, true), nil, true))
	// Absent clients and no events → nothing rendered.
	if got := Clients(ctxFor(80, false, true), nil, false); got != "" {
		t.Errorf("no-events empty clients should render nothing, got %q", got)
	}
}

func TestCompactClientsFoldVersionsAndKeepNamesShort(t *testing.T) {
	clients := append(oneClient(), models.ClientAggregate{
		Key: "aws-cli-new", Name: "aws-cli", Version: "2.16.0", Category: "cli",
		TotalEventCount: 7, DeniedEventCount: 1, LastSeen: "2026-07-24T10:00:00Z",
		Commands: map[string]int{"ua:s3.sync": 2},
	})
	clients = append(clients, models.ClientAggregate{
		Key: "Boto3", Name: "Boto3", Version: "1.34.0", Category: "sdk",
		TotalEventCount: 3, LastSeen: "2026-07-24T09:00:00Z",
	})

	rows := compactClientRows(clients)
	if len(rows) != 2 || rows[0].name != "aws-cli" || rows[0].requests != 37 || rows[0].denied != 1 {
		t.Fatalf("compact clients = %#v", rows)
	}
	if got := topClientSummary(clients); got != "aws-cli +1" {
		t.Fatalf("topClientSummary() = %q, want aws-cli +1", got)
	}
	output := Clients(ctxFor(100, false, true), clients, true)
	if strings.Contains(output, "2.15.0") || strings.Contains(output, "2.16.0") ||
		strings.Contains(output, "API events") {
		t.Fatalf("compact clients expose verbose details:\n%s", output)
	}
	if !strings.Contains(output, "s3.cp (5)") || !strings.Contains(output, "s3.sync (2)") {
		t.Fatalf("compact clients lost client commands:\n%s", output)
	}
}

func TestVerboseClientsKeepDiagnostics(t *testing.T) {
	output := VerboseClients(ctxFor(100, false, true), oneClient(), true)
	for _, want := range []string{"aws-cli 2.15.0", "macos 14.2", "API events:", "client commands:"} {
		if !strings.Contains(output, want) {
			t.Fatalf("verbose clients missing %q:\n%s", want, output)
		}
	}
}

func TestGoldenTopEventsCountDesc(t *testing.T) {
	// Top Events must sort count-descending (not alphabetical). iam:ListRoles (2)
	// must come last despite sorting first alphabetically.
	counts := map[string]int{"s3:GetObject": 20, "s3:PutObject": 8, "iam:ListRoles": 2}
	assertGolden(t, "top_events_count_desc", TopEvents(ctxFor(100, false, true), counts))
}

func TestGoldenDeniedEvents(t *testing.T) {
	// With a per-call breakdown: a count-descending table, denied-accented.
	counts := map[string]int{
		"pricelist.amazonaws.com:ListPriceLists": 3,
		"ce.amazonaws.com:GetCostAndUsage":       1,
		"wafv2.amazonaws.com:ListWebACLs":        1,
	}
	assertGolden(t, "denied_events_breakdown", DeniedEvents(ctxFor(100, false, true), 5, counts))
	assertGolden(t, "denied_events_breakdown_color", DeniedEvents(ctxFor(100, true, true), 5, counts))
	// Total known but no breakdown (older records): explanatory one-line fallback.
	assertGolden(t, "denied_events_count_only", DeniedEvents(ctxFor(80, false, true), 6, nil))
	// No denials: nothing rendered.
	if got := DeniedEvents(ctxFor(80, false, true), 0, nil); got != "" {
		t.Errorf("no denials should render nothing, got %q", got)
	}
}

func TestGoldenSessionOverview(t *testing.T) {
	sess := &models.Session{
		PersonKey: "email#alice@example.com", SK: "sis#session-1",
		RoleName: "AdministratorAccess", RoleARN: "arn:aws:iam::123456789012:role/AdministratorAccess",
		AccountID: "123456789012", EventsCount: 30, ServicesCount: 3,
		StartTime: "2026-07-24T09:00:00Z", EndTime: "2026-07-24T09:45:00Z", DurationMinutes: 45,
		RoleSessionName: "alice@example.com", HasSessionPolicy: true,
	}
	timeLine := ctxFor(100, false, true).Interval(sess.StartTime, sess.EndTime) + " (45m)"
	assertGolden(t, "session_overview", SessionOverview(ctxFor(100, false, true), sess, "Alice Example", timeLine, false))
}

func TestSessionOverviewVerboseShowsInternalIdentifiers(t *testing.T) {
	sess := &models.Session{PersonKey: "email#alice@example.com", SK: "key#abc", Anchor: "key#abc"}
	plain := SessionOverview(ctxFor(100, false, true), sess, "Alice Example", "today", false)
	verbose := SessionOverview(ctxFor(100, false, true), sess, "Alice Example", "today", true)
	if strings.Contains(plain, "Internal SK") || strings.Contains(plain, "Anchor") {
		t.Fatalf("plain overview exposes internals:\n%s", plain)
	}
	if !strings.Contains(verbose, "Internal SK") || !strings.Contains(verbose, "Anchor") {
		t.Fatalf("verbose overview omits internals:\n%s", verbose)
	}
}

func TestSessionOverviewRendersConciseIAMUser(t *testing.T) {
	const key = "iamuser#arn:aws:iam::278835131762:user/testing-trailtool"
	sess := &models.Session{
		PersonKey: key,
		SK:        "win#role#2026-07-26T00:00:00Z",
	}
	got := SessionOverview(ctxFor(100, false, true), sess, models.DisplayPersonKey(key), "2026-07-26", false)
	if !strings.Contains(got, "iamuser:testing-trailtool") || strings.Contains(got, "arn:aws:iam") {
		t.Fatalf("IAM user detail = %q", got)
	}
}

func TestSessionOriginGroupsAssumptionMetadata(t *testing.T) {
	ref := "email#alice@example.com|sis#parent"
	sess := &models.Session{
		RoleSessionName:          "claude-code-worker",
		SessionTags:              map[string]string{"Task": "deploy", "Agent": "claude-code"},
		MCPResource:              "https://aws-mcp.us-east-1.api.aws/mcp",
		AgentAuthorizedBySession: ref,
		SignInSessionArn:         "arn:aws:signin:us-east-1:123456789012:session/abc",
	}
	parent := SessionOriginReference{
		Ref: ref, PersonLabel: "Alice Example",
		Session: &models.Session{RoleName: "Admin", StartTime: "2026-07-24T09:00:00Z"},
	}
	plain := SessionOrigin(ctxFor(100, false, true), sess, parent, false)
	for _, want := range []string{"Origin:", "AWS MCP Server OAuth", "Agent=claude-code, Task=deploy", "Session policy:", "Authorized by:"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("origin missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "Sign-in session") {
		t.Fatalf("plain origin exposes sign-in ARN:\n%s", plain)
	}
	verbose := SessionOrigin(ctxFor(100, false, true), sess, parent, true)
	if !strings.Contains(verbose, "Sign-in session:") {
		t.Fatalf("verbose origin omits sign-in ARN:\n%s", verbose)
	}
}

// TestClientsNoColorParity: color is additive for the Clients section.
func TestClientsNoColorParity(t *testing.T) {
	colored := Clients(ctxFor(100, true, true), mixedFamilies(), true)
	plain := Clients(ctxFor(100, false, true), mixedFamilies(), true)
	if render.StripANSI(colored) != plain {
		t.Error("stripped colored Clients != plain Clients")
	}
}
