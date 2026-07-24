package view

import (
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
			Commands: map[string]int{"ec2:DescribeInstances": 30, "ec2:RunInstances": 20},
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

func TestGoldenTopEventsCountDesc(t *testing.T) {
	// Top Events must sort count-descending (not alphabetical). iam:ListRoles (2)
	// must come last despite sorting first alphabetically.
	counts := map[string]int{"s3:GetObject": 20, "s3:PutObject": 8, "iam:ListRoles": 2}
	assertGolden(t, "top_events_count_desc", TopEvents(ctxFor(100, false, true), counts))
}

func TestGoldenSessionTitleKV(t *testing.T) {
	sess := &models.Session{
		PersonKey: "email#alice@example.com", SK: "sis#session-1",
		RoleName: "AdministratorAccess", RoleARN: "arn:aws:iam::123456789012:role/AdministratorAccess",
		AccountID: "123456789012", EventsCount: 30, ServicesCount: 3,
		StartTime: "2026-07-24T09:00:00Z", EndTime: "2026-07-24T09:45:00Z", DurationMinutes: 45,
	}
	timeLine := ctxFor(100, false, true).Interval(sess.StartTime, sess.EndTime) + " (45m) [3h ago]"
	assertGolden(t, "session_title_kv", SessionTitleKV(ctxFor(100, false, true), sess, "Alice Example", timeLine))
}

// TestClientsNoColorParity: color is additive for the Clients section.
func TestClientsNoColorParity(t *testing.T) {
	colored := Clients(ctxFor(100, true, true), mixedFamilies(), true)
	plain := Clients(ctxFor(100, false, true), mixedFamilies(), true)
	if render.StripANSI(colored) != plain {
		t.Error("stripped colored Clients != plain Clients")
	}
}
