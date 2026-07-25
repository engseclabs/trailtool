package models

import "testing"

func TestApplyRelationshipCountsUsesExactSummary(t *testing.T) {
	counts := RelationshipCounts{
		Exact: true, People: 7, Sessions: 8, Accounts: 2, Roles: 3, Services: 4, Resources: 5,
	}

	person := Person{SessionsCount: 99, AccountsCount: 99, RolesCount: 99, ServicesCount: 99, ResourcesCount: 99}
	person.ApplyRelationshipCounts(counts)
	if person.SessionsCount != 8 || person.AccountsCount != 2 || person.RolesCount != 3 ||
		person.ServicesCount != 4 || person.ResourcesCount != 5 {
		t.Fatalf("person counts = %#v", person)
	}

	session := Session{ServicesCount: 99, ResourcesCount: 99}
	session.ApplyRelationshipCounts(counts)
	if session.ServicesCount != 4 || session.ResourcesCount != 5 {
		t.Fatalf("session counts = %#v", session)
	}

	role := Role{PeopleCount: 99, SessionsCount: 99, AccountsCount: 99}
	role.ApplyRelationshipCounts(counts)
	if role.PeopleCount != 7 || role.SessionsCount != 8 || role.AccountsCount != 2 {
		t.Fatalf("role counts = %#v", role)
	}

	resource := Resource{RolesCount: 99, PeopleCount: 99, SessionsCount: 99}
	resource.ApplyRelationshipCounts(counts)
	if resource.RolesCount != 3 || resource.PeopleCount != 7 || resource.SessionsCount != 8 {
		t.Fatalf("resource counts = %#v", resource)
	}

	account := Account{PeopleCount: 99, SessionsCount: 99, RolesCount: 99, ServicesCount: 99, ResourcesCount: 99}
	account.ApplyRelationshipCounts(counts)
	if account.PeopleCount != 7 || account.SessionsCount != 8 || account.RolesCount != 3 ||
		account.ServicesCount != 4 || account.ResourcesCount != 5 {
		t.Fatalf("account counts = %#v", account)
	}

	service := Service{RolesCount: 99, ResourcesCount: 99, PeopleCount: 99, SessionsCount: 99, AccountsCount: 99}
	service.ApplyRelationshipCounts(counts)
	if service.RolesCount != 3 || service.ResourcesCount != 5 || service.PeopleCount != 7 ||
		service.SessionsCount != 8 || service.AccountsCount != 2 {
		t.Fatalf("service counts = %#v", service)
	}
}

func TestApplyRelationshipCountsKeepsFallbackWithoutSummary(t *testing.T) {
	person := Person{SessionsCount: 4}
	person.ApplyRelationshipCounts(RelationshipCounts{Sessions: 10})
	if person.SessionsCount != 4 {
		t.Fatalf("fallback count = %d, want 4", person.SessionsCount)
	}
}
