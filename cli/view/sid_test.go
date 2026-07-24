package view

import (
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func sess(sid string) models.Session { return models.Session{Sid: sid} }

func TestSidDisplayWidth(t *testing.T) {
	tests := []struct {
		name     string
		sessions []models.Session
		want     int
	}{
		{
			name:     "unique at min width",
			sessions: []models.Session{sess("abc123xxxx"), sess("def456yyyy")},
			want:     sidDisplayMin,
		},
		{
			name: "shared 6-char prefix widens to 7",
			// first 6 chars identical, differ at position 7
			sessions: []models.Session{sess("abc123Xzzz"), sess("abc123Yzzz")},
			want:     7,
		},
		{
			name:     "empty list",
			sessions: nil,
			want:     sidDisplayMin,
		},
		{
			name: "records without sid are ignored for width",
			sessions: []models.Session{sess("abc123xxxx"), sess(""), sess("def456yyyy")},
			want:     sidDisplayMin,
		},
		{
			name:     "single session",
			sessions: []models.Session{sess("abc123xxxx")},
			want:     sidDisplayMin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SidDisplayWidth(tt.sessions); got != tt.want {
				t.Errorf("SidDisplayWidth() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSidDisplayWidthCapsAtFullLen(t *testing.T) {
	// Two identical full-length sids can't be disambiguated; width caps at the
	// full sid length rather than looping forever.
	dup := "aaaaaaaaaaaaaaaa" // 16 chars
	got := SidDisplayWidth([]models.Session{sess(dup), sess(dup)})
	if got != sidFullLen {
		t.Errorf("SidDisplayWidth() = %d, want %d (cap)", got, sidFullLen)
	}
}

func TestShortSid(t *testing.T) {
	s := sess("abcdef0123456789")
	if got := ShortSid(&s, 6); got != "abcdef" {
		t.Errorf("ShortSid width 6 = %q, want %q", got, "abcdef")
	}
	empty := sess("")
	if got := ShortSid(&empty, 6); got != "-" {
		t.Errorf("ShortSid empty = %q, want %q", got, "-")
	}
	// Width beyond the sid length clamps to the sid.
	short := sess("abc")
	if got := ShortSid(&short, 6); got != "abc" {
		t.Errorf("ShortSid over-width = %q, want %q", got, "abc")
	}
}
