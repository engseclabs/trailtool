package models

import "testing"

func TestPIDForPersonKeyGolden(t *testing.T) {
	if got, want := PIDForPersonKey("email#alice@example.com"), "5nmamaaeshnhs6xu"; got != want {
		t.Fatalf("PIDForPersonKey() = %q, want %q", got, want)
	}
}

func TestRIDForResourceGolden(t *testing.T) {
	identifier := "lambda:function:shared-function"
	first := RIDForResource("111111111111", identifier)
	second := RIDForResource("222222222222", identifier)
	if want := "fyf7wfyglmgloz65"; first != want {
		t.Fatalf("RIDForResource() = %q, want %q", first, want)
	}
	if want := "jqu2aa44nwpvvpqr"; second != want {
		t.Fatalf("RIDForResource() = %q, want %q", second, want)
	}
	if first == second {
		t.Fatal("same-named resources in different accounts have the same RID")
	}
}

func TestDerivedNounIDMethodsPreferPopulatedJSONFields(t *testing.T) {
	person := Person{Pid: "custom", PersonKey: "email#alice@example.com"}
	if got := person.PID(); got != "custom" {
		t.Fatalf("Person.PID() = %q, want custom", got)
	}
	resource := Resource{Rid: "custom", AccountID: "111111111111", Identifier: "s3:bucket:example"}
	if got := resource.RID(); got != "custom" {
		t.Fatalf("Resource.RID() = %q, want custom", got)
	}
}
