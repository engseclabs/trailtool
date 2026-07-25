package view

import (
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func TestNounIDDisplayWidths(t *testing.T) {
	people := []models.Person{
		{Pid: "abcdef1aaaaaaaaa"},
		{Pid: "abcdef2bbbbbbbbb"},
	}
	if got := PersonIDDisplayWidth(people); got != 7 {
		t.Fatalf("PersonIDDisplayWidth() = %d, want 7", got)
	}

	roles := []models.Role{
		{RoleSelector: "abcdef1aaaaaaaaa"},
		{RoleSelector: "abcdef2bbbbbbbbb"},
	}
	if got := RoleIDDisplayWidth(roles); got != 7 {
		t.Fatalf("RoleIDDisplayWidth() = %d, want 7", got)
	}

	resources := []models.Resource{
		{Rid: "1234567aaaaaaaaa"},
		{Rid: "1234568bbbbbbbbb"},
	}
	if got := ResourceIDDisplayWidth(resources); got != 7 {
		t.Fatalf("ResourceIDDisplayWidth() = %d, want 7", got)
	}
}

func TestNounIDDisplayWidthDefaultsToSix(t *testing.T) {
	people := []models.Person{{Pid: "abcdef1aaaaaaaaa"}, {Pid: "ghijkl2bbbbbbbbb"}}
	if got := PersonIDDisplayWidth(people); got != 6 {
		t.Fatalf("PersonIDDisplayWidth() = %d, want 6", got)
	}
}

func TestShortRoleID(t *testing.T) {
	role := models.Role{RoleSelector: "abcdef1aaaaaaaaa"}
	if got := ShortRoleID(&role, 7); got != "abcdef1" {
		t.Fatalf("ShortRoleID() = %q, want abcdef1", got)
	}
}
