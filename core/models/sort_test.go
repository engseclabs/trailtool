package models

import "testing"

func TestSortSessionsForList(t *testing.T) {
	input := []Session{
		{Sid: "bbbbbb", StartTime: "2026-07-24T10:00:00Z"},
		{Sid: "cccccc", StartTime: "2026-07-24T09:00:00Z"},
		{Sid: "aaaaaa", StartTime: "2026-07-24T10:00:00Z"},
	}

	SortSessionsForList(input, false)
	assertSessionIDs(t, input, []string{"cccccc", "aaaaaa", "bbbbbb"})

	SortSessionsForList(input, true)
	assertSessionIDs(t, input, []string{"aaaaaa", "bbbbbb", "cccccc"})
}

func assertSessionIDs(t *testing.T, sessions []Session, want []string) {
	t.Helper()
	for i := range want {
		if sessions[i].Sid != want[i] {
			t.Fatalf("session %d = %q, want %q", i, sessions[i].Sid, want[i])
		}
	}
}
