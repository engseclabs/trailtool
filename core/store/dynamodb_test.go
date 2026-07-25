package store

import (
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func TestNounListSorters(t *testing.T) {
	people := []models.Person{
		{PersonKey: "email#b@example.com", LastSeen: "2026-07-24"},
		{PersonKey: "email#c@example.com", LastSeen: "2026-07-23"},
		{PersonKey: "email#a@example.com", LastSeen: "2026-07-24"},
	}
	sortPeople(people)
	if people[0].PersonKey != "email#a@example.com" ||
		people[1].PersonKey != "email#b@example.com" ||
		people[2].PersonKey != "email#c@example.com" {
		t.Fatalf("people order = %#v", people)
	}
	for i := range people {
		if people[i].Pid == "" {
			t.Fatalf("person %q has no derived PID", people[i].PersonKey)
		}
	}

	roles := []models.Role{
		{ARN: "arn:role/b", LastSeen: "2026-07-24"},
		{ARN: "arn:role/c", LastSeen: "2026-07-23"},
		{ARN: "arn:role/a", LastSeen: "2026-07-24"},
	}
	sortRoles(roles)
	if roles[0].ARN != "arn:role/a" || roles[1].ARN != "arn:role/b" || roles[2].ARN != "arn:role/c" {
		t.Fatalf("roles order = %#v", roles)
	}
	for i := range roles {
		if roles[i].RoleSelector == "" {
			t.Fatalf("role %q has no derived role ID", roles[i].ARN)
		}
	}

	resources := []models.Resource{
		{AccountID: "222", Identifier: "lambda:function:a", LastSeen: "2026-07-24"},
		{AccountID: "111", Identifier: "lambda:function:b", LastSeen: "2026-07-24"},
		{AccountID: "111", Identifier: "lambda:function:a", LastSeen: "2026-07-24"},
	}
	sortResources(resources)
	if resources[0].Identifier != "lambda:function:a" ||
		resources[1].Identifier != "lambda:function:b" ||
		resources[2].AccountID != "222" {
		t.Fatalf("resources order = %#v", resources)
	}
	for i := range resources {
		if resources[i].Rid == "" {
			t.Fatalf("resource %q has no derived RID", resources[i].Identifier)
		}
	}

	accounts := []models.Account{
		{AccountID: "222", LastSeen: "2026-07-24"},
		{AccountID: "333", LastSeen: "2026-07-23"},
		{AccountID: "111", LastSeen: "2026-07-24"},
	}
	sortAccounts(accounts)
	if accounts[0].AccountID != "111" || accounts[1].AccountID != "222" || accounts[2].AccountID != "333" {
		t.Fatalf("accounts order = %#v", accounts)
	}

	services := []models.Service{
		{EventSource: "s3.amazonaws.com", LastSeen: "2026-07-24"},
		{EventSource: "sts.amazonaws.com", LastSeen: "2026-07-23"},
		{EventSource: "lambda.amazonaws.com", LastSeen: "2026-07-24"},
	}
	sortServices(services)
	if services[0].EventSource != "lambda.amazonaws.com" ||
		services[1].EventSource != "s3.amazonaws.com" ||
		services[2].EventSource != "sts.amazonaws.com" {
		t.Fatalf("services order = %#v", services)
	}
}

func TestRolesByRoleIDPrefix(t *testing.T) {
	roles := []models.Role{
		{RoleSelector: "abcdef1aaaaaaaaa", ARN: "arn:aws:iam::111:role/Admin"},
		{RoleSelector: "abcdef2bbbbbbbbb", ARN: "arn:aws:iam::222:role/Admin"},
		{RoleSelector: "ghijkl3ccccccccc", ARN: "arn:aws:iam::111:role/ReadOnly"},
	}

	got := rolesByRoleIDPrefix(roles, "abcdef")
	if len(got) != 2 || got[0].RoleSelector != "abcdef1aaaaaaaaa" || got[1].RoleSelector != "abcdef2bbbbbbbbb" {
		t.Fatalf("prefix matches = %#v", got)
	}
	if got := rolesByRoleIDPrefix(roles, "missing"); len(got) != 0 {
		t.Fatalf("missing prefix matches = %#v", got)
	}
}

func TestRolesByExactName(t *testing.T) {
	roles := []models.Role{
		{ARN: "arn:aws:iam::222:role/Admin", Name: "Admin", AccountID: "222"},
		{ARN: "arn:aws:iam::111:role/Admin", Name: "Admin", AccountID: "111"},
		{ARN: "arn:aws:iam::111:role/AdminReadOnly", Name: "AdminReadOnly", AccountID: "111"},
	}

	got := rolesByExactName(roles, "Admin", "")
	if len(got) != 2 || got[0].AccountID != "111" || got[1].AccountID != "222" {
		t.Fatalf("exact matches = %#v", got)
	}
	scoped := rolesByExactName(roles, "Admin", "222")
	if len(scoped) != 1 || scoped[0].AccountID != "222" {
		t.Fatalf("scoped matches = %#v", scoped)
	}
}
