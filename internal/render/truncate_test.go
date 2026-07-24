package render

import "testing"

func TestTruncate(t *testing.T) {
	uni := Context{Unicode: true}
	asc := Context{Unicode: false}

	tests := []struct {
		name string
		ctx  Context
		in   string
		max  int
		want string
	}{
		{"fits unchanged", uni, "short", 10, "short"},
		{"exact fit", uni, "exactly10!", 10, "exactly10!"},
		{"unicode middle", uni, "aws-reserved/sso/AdministratorAccess", 20, "aws-reserv…torAccess"},
		{"ascii middle", asc, "aws-reserved/sso/AdministratorAccess", 20, "aws-reser...orAccess"},
		{"zero max", uni, "anything", 0, ""},
		{"max below marker unicode", uni, "abcdef", 1, "…"},
		{"max below marker ascii", asc, "abcdef", 2, ".."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ctx.Truncate(tt.in, tt.max)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
			if w := runeLen(got); w > tt.max && tt.max > 0 {
				t.Errorf("Truncate result %q width %d exceeds max %d", got, w, tt.max)
			}
		})
	}
}

func runeLen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}
