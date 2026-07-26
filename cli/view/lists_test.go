package view

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

// fixedNow anchors relative timestamps so golden output is deterministic.
var fixedNow = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

var update = flag.Bool("update", false, "update golden files")

// ctxFor builds a render.Context for golden tests without touching the terminal.
func ctxFor(width int, color, unicode bool) render.Context {
	return render.Context{Color: color, Unicode: unicode, Width: width, Now: fixedNow}
}

func samplePeople() []models.Person {
	return []models.Person{
		{PersonKey: "email#alice@example.com", DisplayName: "Alice Example", EventsCount: 320, SessionsCount: 12, RolesCount: 3, AccountsCount: 2, DeniedEventCount: 4, LastSeen: "2026-07-24T10:00:00Z"},
		{PersonKey: "idc#d-1234567890#abcd-ef01", EventsCount: 44, SessionsCount: 4, RolesCount: 1, AccountsCount: 1, DeniedEventCount: 0, LastSeen: "2026-07-23T09:00:00Z"},
	}
}

func sampleRoles() []models.Role {
	return []models.Role{
		{ARN: "arn:aws:iam::123456789012:role/AdministratorAccess", Name: "AdministratorAccess", AccountID: "123456789012", TotalEvents: 420, PeopleCount: 5, SessionsCount: 30, TotalDeniedEvents: 7, LastSeen: "2026-07-24T11:00:00Z"},
		{ARN: "arn:aws:iam::123456789012:role/ReadOnly", Name: "ReadOnly", AccountID: "123456789012", TotalEvents: 88, PeopleCount: 2, SessionsCount: 9, TotalDeniedEvents: 0, LastSeen: "2026-07-22T08:00:00Z"},
	}
}

func sampleAccounts() []models.Account {
	return []models.Account{
		{AccountID: "123456789012", AccountName: "production", EventsCount: 508, SessionsCount: 39, PeopleCount: 7, RolesCount: 2, ServicesCount: 14, ResourcesCount: 22, TotalDeniedEvents: 7, LastSeen: "2026-07-24T11:00:00Z"},
		{AccountID: "210987654321", EventsCount: 42, SessionsCount: 3, PeopleCount: 1, RolesCount: 1, ServicesCount: 5, ResourcesCount: 8, TotalDeniedEvents: 0, LastSeen: "2026-07-22T08:00:00Z"},
	}
}

func sampleServices() []models.Service {
	return []models.Service{
		{EventSource: "s3.amazonaws.com", TotalEvents: 300, TotalDeniedEvents: 4, RolesCount: 5, ResourcesCount: 10, PeopleCount: 4, SessionsCount: 20, AccountsCount: 2, LastSeen: "2026-07-24T11:00:00Z"},
		{EventSource: "lambda.amazonaws.com", TotalEvents: 120, TotalDeniedEvents: 0, RolesCount: 3, ResourcesCount: 6, PeopleCount: 2, SessionsCount: 8, AccountsCount: 1, LastSeen: "2026-07-23T09:00:00Z"},
	}
}

func sampleResources() []models.Resource {
	return []models.Resource{
		{Identifier: "lambda:function:shared-function", Type: "lambda:function", AccountID: "123456789012", TotalEvents: 80, TotalDeniedEvents: 2, ClickOpsCount: 3, RolesCount: 2, SessionsCount: 5, LastSeen: "2026-07-24T11:00:00Z"},
		{Identifier: "lambda:function:shared-function", Type: "lambda:function", AccountID: "210987654321", TotalEvents: 40, TotalDeniedEvents: 0, ClickOpsCount: 0, RolesCount: 1, SessionsCount: 2, LastSeen: "2026-07-23T09:00:00Z"},
	}
}

func sampleSessions() []models.Session {
	return []models.Session{
		{
			Sid: "k7m2qp3x", PersonKey: "email#alice@example.com",
			StartTime: "2026-07-24T09:00:00Z", DurationMinutes: 45, EventsCount: 30,
			AccountID: "123456789012", RoleName: "aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_AdministratorAccess_7d88aa2a",
			RoleSessionName: "alice@example.com",
			Clients: []models.ClientAggregate{
				{Key: "aws-cli", Name: "aws-cli", Version: "2.15.0", TotalEventCount: 25},
				{Key: "Boto3", Name: "Boto3", Version: "1.34.0", TotalEventCount: 5},
			},
			SessionTags:      map[string]string{"Environment": "production", "Team": "platform"},
			HasSessionPolicy: true,
		},
		{
			Sid: "q9w1e7rt", PersonKey: "idc#d-1234567890#abcd",
			StartTime: "2026-07-24T08:00:00Z", DurationMinutes: 5, EventsCount: 3,
			AccountID: "123456789012", RoleName: "ReadOnly",
			AssumedFromSession: "email#alice@example.com|sis#session-1",
		},
	}
}

func label(key string) string {
	if key == "email#alice@example.com" {
		return "Alice Example"
	}
	return ShortPersonKey(key)
}

// assertGolden writes or compares a golden file.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run -update to create): %v", name, err)
	}
	if got != string(want) {
		t.Errorf("golden mismatch %s:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestGoldenPeople(t *testing.T) {
	assertGolden(t, "people_w100_plain", People(ctxFor(100, false, true), samplePeople()))
	assertGolden(t, "people_empty", People(ctxFor(80, false, true), nil))
}

func TestGoldenRoles(t *testing.T) {
	// Denied column: nonzero accented, zero muted-but-present.
	assertGolden(t, "roles_w100_plain", Roles(ctxFor(100, false, true), sampleRoles()))
	assertGolden(t, "roles_w100_color", Roles(ctxFor(100, true, true), sampleRoles()))
}

func TestGoldenOtherNounLists(t *testing.T) {
	assertGolden(t, "accounts_w132_plain", Accounts(ctxFor(132, false, true), sampleAccounts()))
	assertGolden(t, "services_w132_plain", Services(ctxFor(132, false, true), sampleServices()))
	assertGolden(t, "resources_w132_plain", Resources(ctxFor(132, false, true), sampleResources()))
}

func TestGoldenSessionList(t *testing.T) {
	// Responsive tiers: wide shows all columns, narrow drops collapsible ones.
	assertGolden(t, "sessions_w180_plain", SessionList(ctxFor(180, false, true), sampleSessions(), 6, false, label))
	assertGolden(t, "sessions_w132_plain", SessionList(ctxFor(132, false, true), sampleSessions(), 6, false, label))
	assertGolden(t, "sessions_w80_plain", SessionList(ctxFor(80, false, true), sampleSessions(), 6, false, label))
	assertGolden(t, "sessions_w60_ascii", SessionList(ctxFor(60, false, false), sampleSessions(), 6, false, label))
	assertGolden(t, "sessions_empty", SessionList(ctxFor(80, false, true), nil, 6, false, label))
}

func TestSessionListContextSummaries(t *testing.T) {
	got := SessionList(ctxFor(180, false, true), sampleSessions(), 6, false, label)
	for _, want := range []string{"aws-cli +1", "alice@example.com", "Environment=production +1", "yes"} {
		if !strings.Contains(got, want) {
			t.Fatalf("session list missing %q:\n%s", want, got)
		}
	}
}

// TestListsNoColorParity proves color is additive for the list views: stripping
// ANSI from a colored render equals the plain render (§9).
func TestListsNoColorParity(t *testing.T) {
	colored := Roles(ctxFor(100, true, true), sampleRoles())
	plain := Roles(ctxFor(100, false, true), sampleRoles())
	if render.StripANSI(colored) != plain {
		t.Error("stripped colored Roles != plain Roles")
	}
	cSess := SessionList(ctxFor(132, true, true), sampleSessions(), 6, false, label)
	pSess := SessionList(ctxFor(132, false, true), sampleSessions(), 6, false, label)
	if render.StripANSI(cSess) != pSess {
		t.Error("stripped colored SessionList != plain SessionList")
	}
}

func TestClickOpsUsesStableResourceSelectors(t *testing.T) {
	got := ClickOps(ctxFor(132, false, true), sampleResources(), label)
	if !strings.Contains(got, "RID") || strings.Contains(got, "#  RESOURCE") {
		t.Fatalf("ClickOps selector header is not RID:\n%s", got)
	}
}

func TestRoleIDRemainsCopyableAtNarrowWidths(t *testing.T) {
	roles := sampleRoles()
	got := Roles(ctxFor(60, false, true), roles[:1])
	want := roles[0].RoleID()[:nounIDDisplayMin]
	if !strings.Contains(got, want) {
		t.Fatalf("role ID %q is missing:\n%s", want, got)
	}
	if strings.Contains(got, roles[0].ARN) {
		t.Fatalf("role list still exposes the ARN as its selector:\n%s", got)
	}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if width := utf8.RuneCountInString(line); width > 60 {
			t.Fatalf("role list line is %d columns wide:\n%s", width, got)
		}
	}
}
