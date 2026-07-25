package view

import (
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

const enrichedSessionRef = "email#alice@example.com|sis#session-1"

func sampleEnrichedRelated() models.RelatedNouns {
	related := models.NewRelatedNouns()
	related.People = []models.RelatedPerson{{
		Person: models.Person{
			Pid: "5nmamaaeshnhs6xu", PersonKey: "email#alice@example.com",
			DisplayName: "Alice Example",
		},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
	}}
	related.Sessions = []models.RelatedSession{{
		Session: models.Session{
			Sid: models.SidForRef(enrichedSessionRef), PersonKey: "email#alice@example.com", SK: "sis#session-1",
			RoleName: "DeployRole", AccountID: "123456789012", SessionType: "web",
			EventsCount: 12, StartTime: "2026-07-24T09:00:00Z",
		},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
	}}
	related.Accounts = []models.RelatedAccount{{
		Account:            models.Account{AccountID: "123456789012", AccountName: "production"},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
	}}
	related.Roles = []models.RelatedRole{{
		Role:               models.Role{ARN: "arn:aws:iam::123456789012:role/DeployRole"},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
	}}
	related.Services = []models.RelatedService{{
		Service:            models.Service{EventSource: "lambda.amazonaws.com"},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:44:00Z"},
	}}
	related.Resources = []models.RelatedResource{{
		Resource: models.Resource{
			Rid: "fyf7wfyglmgloz65", Identifier: "lambda:function:worker", AccountID: "123456789012",
		},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:43:00Z"},
	}}
	return related
}

func sampleAccountDetail() *models.AccountDetail {
	return &models.AccountDetail{
		Account: models.Account{
			AccountID: "123456789012", AccountName: "production",
			FirstSeen: "2026-07-01T08:00:00Z", LastSeen: "2026-07-24T09:45:00Z",
			EventsCount: 120, PeopleCount: 1, SessionsCount: 4, RolesCount: 2,
			ServicesCount: 3, ResourcesCount: 5, TotalDeniedEvents: 3, ClickOpsCount: 2,
			TopEventNames:       map[string]int{"Invoke": 80, "UpdateFunctionCode": 40},
			TopDeniedEventNames: map[string]int{"DeleteFunction": 3},
		},
		Related: sampleEnrichedRelated(),
	}
}

func sampleRoleDetail() *models.RoleDetail {
	return &models.RoleDetail{
		Role: models.Role{
			ARN: "arn:aws:iam::123456789012:role/DeployRole", Name: "DeployRole",
			AccountID: "123456789012", FirstSeen: "2026-07-01T08:00:00Z", LastSeen: "2026-07-24T09:45:00Z",
			TotalEvents: 120, TotalDeniedEvents: 3, PeopleCount: 1, SessionsCount: 4,
			TopEventNames:       map[string]int{"Invoke": 80, "UpdateFunctionCode": 40},
			TopDeniedEventNames: map[string]int{"DeleteFunction": 3},
			ServicesCount:       map[string]int{"lambda.amazonaws.com": 120},
			ResourceAccesses: []models.ResourceAccessItem{{
				Service: "lambda.amazonaws.com", EventName: "Invoke",
				Resource: "lambda:function:worker", ResourceAccountID: "123456789012", Count: 80,
			}},
			DeniedResourceAccesses: []models.ResourceAccessItem{{
				Service: "lambda.amazonaws.com", EventName: "DeleteFunction",
				Resource: "lambda:function:worker", ResourceAccountID: "123456789012", Count: 2,
				PolicyARN:  "arn:aws:organizations::123456789012:policy/o-example/service_control_policy/p-deny",
				PolicyType: "SCP", ErrorMessage: "blocked by organization policy",
			}},
			DeniedEventAccesses: []models.EventAccessItem{{
				Service: "lambda.amazonaws.com", EventName: "ListFunctions", Count: 1,
				PolicyType: "identity-based", ErrorMessage: "no identity policy allows this action",
			}},
		},
		Related: sampleEnrichedRelated(),
	}
}

func sampleServiceDetail() *models.ServiceDetail {
	return &models.ServiceDetail{
		Service: models.Service{
			EventSource: "lambda.amazonaws.com", DisplayName: "AWS Lambda", Category: "Compute",
			FirstSeen: "2026-07-01T08:00:00Z", LastSeen: "2026-07-24T09:45:00Z",
			TotalEvents: 120, TotalDeniedEvents: 3, RolesCount: 2, ResourcesCount: 5,
			PeopleCount: 1, SessionsCount: 4, AccountsCount: 1,
			TopEventNames:       map[string]int{"Invoke": 80, "UpdateFunctionCode": 40},
			TopDeniedEventNames: map[string]int{"DeleteFunction": 3},
		},
		Related: sampleEnrichedRelated(),
	}
}

func sampleSessionDetail() *models.SessionDetail {
	return &models.SessionDetail{
		Session: models.Session{
			Sid: models.SidForRef(enrichedSessionRef), PersonKey: "email#alice@example.com",
			SK: "sis#session-1", Anchor: "sis#credential-1", SessionType: "web",
			StartTime: "2026-07-24T09:00:00Z", EndTime: "2026-07-24T09:45:00Z", DurationMinutes: 45,
			AccountID: "123456789012", RoleARN: "arn:aws:iam::123456789012:role/DeployRole",
			RoleName: "DeployRole", EventsCount: 120, ServicesCount: 1, ResourcesCount: 1,
			SourceIPs:         []string{"203.0.113.8", "198.51.100.4"},
			EventCounts:       map[string]int{"Invoke": 80, "UpdateFunctionCode": 40},
			ResourcesAccessed: map[string]int{"lambda:function:worker": 120},
			ResourceAccesses: []models.ResourceAccess{{
				Service: "lambda.amazonaws.com", EventName: "Invoke",
				Resource: "lambda:function:worker", ResourceAccountID: "123456789012", Count: 80,
			}},
			DeniedEventCount: 3, DeniedEventCounts: map[string]int{"DeleteFunction": 3},
			DeniedResourceAccesses: []models.ResourceAccess{{
				Service: "lambda.amazonaws.com", EventName: "DeleteFunction",
				Resource: "lambda:function:worker", ResourceAccountID: "123456789012", Count: 3,
				PolicyType: "SCP", ErrorMessage: strings.Repeat("blocked by organization policy ", 8),
			}},
			ClickOpsEventCount: 3, ClickOpsEventCounts: map[string]int{"UpdateFunctionCode": 3},
			Summary:      "Updated the worker function through the console.",
			SummaryModel: "anthropic.claude-sonnet", SummaryGeneratedAt: "2026-07-24T10:00:00Z",
		},
		Related: sampleEnrichedRelated(),
	}
}

func renderSampleSessionDetail(width int, includeDeniedDetails bool) string {
	detail := sampleSessionDetail()
	session := &detail.Session
	ctx := ctxFor(width, false, true)
	timeLine := ctx.Interval(session.StartTime, session.EndTime) + " (45m)"
	var b strings.Builder
	b.WriteString(SessionTitleKV(ctx, session, "Alice Example", timeLine))
	if includeDeniedDetails {
		b.WriteString(DeniedEvents(ctx, session.DeniedEventCount, session.DeniedEventCounts))
	}
	b.WriteString(SessionClickOps(ctx, session.ClickOpsEventCount, session.ClickOpsEventCounts))
	b.WriteString(TopEvents(ctx, session.EventCounts))
	b.WriteString(ResourcesAccessed(ctx, session.ResourcesAccessed))
	b.WriteString(SessionResourceActivity(ctx, session.ResourceAccesses))
	if includeDeniedDetails {
		b.WriteString(SessionDeniedActivity(ctx, session.DeniedResourceAccesses, session.DeniedEventAccesses))
	}
	b.WriteString(SessionSummary(ctx, session))
	b.WriteString(SessionRelationships(ctx, detail))
	return b.String()
}

func TestGoldenEnrichedDetails(t *testing.T) {
	assertGolden(t, "account_detail_w132_plain", AccountDetail(ctxFor(132, false, true), sampleAccountDetail(), true))
	assertGolden(t, "role_detail_w132_plain", RoleDetail(ctxFor(132, false, true), sampleRoleDetail(), true))
	assertGolden(t, "service_detail_w132_plain", ServiceDetail(ctxFor(132, false, true), sampleServiceDetail(), true))
	assertGolden(t, "session_detail_enriched_w132_plain", renderSampleSessionDetail(132, true))
}

func TestEnrichedDetailsKeepSelectorsAtNarrowWidths(t *testing.T) {
	for _, width := range []int{60, 80, 100} {
		role := RoleDetail(ctxFor(width, false, true), sampleRoleDetail(), true)
		if !strings.Contains(role, "arn:aws:iam::123456789012:role/DeployRole") {
			t.Fatalf("width %d lost role ARN:\n%s", width, role)
		}
		session := renderSampleSessionDetail(width, true)
		sid := models.SidForRef(enrichedSessionRef)
		if !strings.Contains(session, sid) {
			t.Fatalf("width %d lost session SID %q:\n%s", width, sid, session)
		}
	}
}

func TestBoundedErrorNormalizesAndTruncates(t *testing.T) {
	got := boundedError(strings.Repeat("long error\n", 20))
	if strings.Contains(got, "\n") || !strings.HasSuffix(got, "…") {
		t.Fatalf("boundedError() = %q", got)
	}
}

func TestEnrichedDetailsNoColorParity(t *testing.T) {
	colored := RoleDetail(ctxFor(132, true, true), sampleRoleDetail(), true)
	plain := RoleDetail(ctxFor(132, false, true), sampleRoleDetail(), true)
	if render.StripANSI(colored) != plain {
		t.Fatal("stripped colored role detail differs from plain output")
	}
}

func TestDeniedActivityDetailsAreOptIn(t *testing.T) {
	ctx := ctxFor(132, false, true)
	outputs := map[string]string{
		"account": AccountDetail(ctx, sampleAccountDetail(), false),
		"role":    RoleDetail(ctx, sampleRoleDetail(), false),
		"service": ServiceDetail(ctx, sampleServiceDetail(), false),
		"session": renderSampleSessionDetail(132, false),
	}
	for name, output := range outputs {
		if strings.Contains(output, "DeleteFunction") || strings.Contains(output, "Denied Activity Details") {
			t.Fatalf("%s detail included denied breakdown by default:\n%s", name, output)
		}
		if !strings.Contains(output, "Denied Events") {
			t.Fatalf("%s detail lost denied summary count:\n%s", name, output)
		}
	}
}

func TestEnrichedDetailsOmitExploreSection(t *testing.T) {
	ctx := ctxFor(132, false, true)
	outputs := []string{
		AccountDetail(ctx, sampleAccountDetail(), true),
		RoleDetail(ctx, sampleRoleDetail(), true),
		ServiceDetail(ctx, sampleServiceDetail(), true),
		renderSampleSessionDetail(132, true),
	}
	for _, output := range outputs {
		if strings.Contains(output, "Explore:") {
			t.Fatalf("detail included Explore section:\n%s", output)
		}
	}
}
