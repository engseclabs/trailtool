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
