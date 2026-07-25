package view

import (
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

func samplePersonDetail() *models.PersonDetail {
	related := models.NewRelatedNouns()
	related.Sessions = []models.RelatedSession{
		{
			Session: models.Session{
				Sid:       models.SidForRef("email#alice@example.com|sis#session-1"),
				PersonKey: "email#alice@example.com", SK: "sis#session-1",
				RoleName: "DeployRole", AccountID: "123456789012", SessionType: "cli",
				EventsCount: 30, StartTime: "2026-07-24T09:00:00Z",
			},
			RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
		},
	}
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

	return &models.PersonDetail{
		Person: models.Person{
			Pid: "5nmamaaeshnhs6xu", PersonKey: "email#alice@example.com", Tier: 1,
			Email: "alice@example.com", EmailsSeen: []string{"a.smith@example.com", "alice@example.com"},
			DisplayName: "Alice Example", FirstSeen: "2026-07-01T08:00:00Z", LastSeen: "2026-07-24T09:45:00Z",
			EventsCount: 120, SessionsCount: 4, AccountsCount: 1, RolesCount: 2,
			ServicesCount: 3, ResourcesCount: 5, DeniedEventCount: 3,
			TopDeniedEventNames: map[string]int{"iam.amazonaws.com:CreateRole": 2, "s3.amazonaws.com:DeleteBucket": 1},
		},
		Related: related,
	}
}

func sampleResourceDetail() *models.ResourceDetail {
	related := models.NewRelatedNouns()
	related.Roles = []models.RelatedRole{{
		Role:               models.Role{ARN: "arn:aws:iam::123456789012:role/DeployRole"},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
	}}
	related.Services = []models.RelatedService{{
		Service:            models.Service{EventSource: "lambda.amazonaws.com"},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:44:00Z"},
	}}
	related.People = []models.RelatedPerson{{
		Person: models.Person{
			Pid: "5nmamaaeshnhs6xu", PersonKey: "email#alice@example.com", DisplayName: "Alice Example",
		},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
	}}
	related.Sessions = []models.RelatedSession{{
		Session: models.Session{
			Sid:       models.SidForRef("email#alice@example.com|sis#session-1"),
			PersonKey: "email#alice@example.com", SK: "sis#session-1",
			RoleName: "DeployRole", AccountID: "123456789012", SessionType: "web",
			EventsCount: 12, StartTime: "2026-07-24T09:00:00Z",
		},
		RelationshipBounds: models.RelationshipBounds{RelationshipLastSeen: "2026-07-24T09:45:00Z"},
	}}

	return &models.ResourceDetail{
		Resource: models.Resource{
			Rid: "fyf7wfyglmgloz65", ResourceKey: "123456789012#encoded",
			Identifier: "lambda:function:worker", Type: "lambda:function",
			ARN: "arn:aws:lambda:us-east-1:123456789012:function:worker", Name: "worker",
			AccountID: "123456789012", TotalEvents: 80, RolesCount: 2, PeopleCount: 1, SessionsCount: 4,
			TopEventNames:     map[string]int{"UpdateFunctionCode": 12, "Invoke": 68},
			TotalDeniedEvents: 2, TopDeniedEventNames: map[string]int{"DeleteFunction": 2},
			ClickOpsCount: 3, FirstSeen: "2026-07-01T08:00:00Z", LastSeen: "2026-07-24T09:45:00Z",
			ClickOpsAccesses: []models.ClickOpsAccess{{
				SessionRef: "email#alice@example.com|sis#session-1", PersonKey: "email#alice@example.com",
				EventName: "UpdateFunctionCode", EventCount: 3, AccessTime: "2026-07-24T09:30:00Z",
			}},
		},
		Related: related,
	}
}

func TestGoldenPersonDetail(t *testing.T) {
	for _, width := range []int{60, 80, 100, 132} {
		assertGolden(t, "person_detail_w"+n(width)+"_plain", PersonDetail(ctxFor(width, false, true), samplePersonDetail(), true))
	}
}

func TestGoldenResourceDetail(t *testing.T) {
	for _, width := range []int{60, 80, 100, 132} {
		assertGolden(t, "resource_detail_w"+n(width)+"_plain", ResourceDetail(ctxFor(width, false, true), sampleResourceDetail(), true))
	}
}

func TestNounDetailsNoColorParity(t *testing.T) {
	colored := PersonDetail(ctxFor(100, true, true), samplePersonDetail(), true)
	plain := PersonDetail(ctxFor(100, false, true), samplePersonDetail(), true)
	if render.StripANSI(colored) != plain {
		t.Fatal("stripped colored person detail differs from plain output")
	}
}

func TestNounDetailsOmitExploreSection(t *testing.T) {
	ctx := ctxFor(100, false, true)
	for _, output := range []string{
		PersonDetail(ctx, samplePersonDetail(), true),
		ResourceDetail(ctx, sampleResourceDetail(), true),
	} {
		if strings.Contains(output, "Explore:") {
			t.Fatalf("detail included Explore section:\n%s", output)
		}
	}
}

func TestNounDeniedBreakdownsAreOptIn(t *testing.T) {
	ctx := ctxFor(100, false, true)
	outputs := map[string]string{
		"person":   PersonDetail(ctx, samplePersonDetail(), false),
		"resource": ResourceDetail(ctx, sampleResourceDetail(), false),
	}
	for name, output := range outputs {
		if strings.Contains(output, "CreateRole") || strings.Contains(output, "DeleteFunction") {
			t.Fatalf("%s detail included denied breakdown by default:\n%s", name, output)
		}
		if !strings.Contains(output, "Denied Events") {
			t.Fatalf("%s detail lost denied summary count:\n%s", name, output)
		}
	}
}
