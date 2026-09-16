package view

import (
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

// TestSessionRoleLabel pins the ROLE column for principals that have no role.
// A blank ROLE was the original symptom that surfaced the roleless-session bug;
// IAM users and root have no role by definition, so the column names them by
// their own identifier rather than going empty.
func TestSessionRoleLabel(t *testing.T) {
	const ssoRole = "aws-reserved/sso.amazonaws.com/AWSReservedSSO_TestAccess_0000000000000000"
	tests := []struct {
		name string
		sess models.Session
		long bool
		want string
	}{
		{
			name: "sso role shortens (region-scoped path)",
			sess: models.Session{RoleName: "aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_TestAccess_0000000000000000"},
			want: "TestAccess",
		},
		{
			name: "sso role shortens (no region segment)",
			sess: models.Session{RoleName: ssoRole},
			want: "TestAccess",
		},
		{
			name: "sso role in full when long",
			sess: models.Session{RoleName: ssoRole},
			long: true,
			want: ssoRole,
		},
		{
			name: "iam user from role arn",
			sess: models.Session{RoleARN: "arn:aws:iam::111111111111:user/deploy-bot"},
			want: "user:deploy-bot",
		},
		{
			name: "iam user with a path",
			sess: models.Session{RoleARN: "arn:aws:iam::111111111111:user/eng/ci/deploy-bot"},
			want: "user:deploy-bot",
		},
		{
			name: "iam user from person key when role arn is absent",
			sess: models.Session{PersonKey: "iamuser#arn:aws:iam::111111111111:user/deploy-bot"},
			want: "user:deploy-bot",
		},
		{
			name: "root",
			sess: models.Session{PersonKey: "root#111111111111"},
			want: "root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SessionRoleLabel(&tt.sess, tt.long); got != tt.want {
				t.Errorf("SessionRoleLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}
