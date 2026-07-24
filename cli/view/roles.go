package view

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/internal/render"
)

var ssoRoleRe = regexp.MustCompile(`^aws-reserved/sso\.amazonaws\.com/[^/]+/AWSReservedSSO_([^_]+)_[0-9a-f]+$`)

// ShortRoleName returns a shortened display name for SSO-managed roles.
// For aws-reserved/sso.amazonaws.com/.../AWSReservedSSO_<Name>_<hash>, it returns <Name>.
func ShortRoleName(name string) string {
	if m := ssoRoleRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return name
}

// ChainedMarks renders the CHAINED column: the session's relationships to other
// sessions, each naming the other end by its short SID so the two rows of an edge
// cross-reference regardless of list ordering or filters. An incoming mark
// (SymSource, "←"/"<-") points at the session that created this one; an outgoing
// mark (SymLineage, "→"/"->") points at what this session created. The verb
// ("assumed"/"granted") carries the direction, so the glyph is redundant
// reinforcement rather than the sole cue — the column reads correctly in mono,
// no-color, ASCII terminals (§4.3). A session may be both a parent and a child (a
// chained session that further chains), so marks accumulate.
func ChainedMarks(ctx render.Context, sess *models.Session) string {
	in := ctx.Symbol(render.SymSource)
	out := ctx.Symbol(render.SymLineage)
	var marks []string

	// Incoming edges — how this session was created.
	if ref := sess.AgentAuthorizedBySession; ref != "" && ref != sess.Ref() {
		marks = append(marks, in+" granted by "+SidForRefShort(ref))
	} else if ref := sess.LoginGrantedBySession; ref != "" {
		marks = append(marks, in+" granted by "+SidForRefShort(ref))
	}
	if ref := sess.AssumedFromSession; ref != "" {
		marks = append(marks, in+" assumed by "+SidForRefShort(ref))
	}

	// Outgoing edges — what this session created. When there's exactly one target
	// we name it by SID; for several we fall back to a count (the detail view lists
	// them). ChainedSessionRefs is preferred over ChainedRoles because a ref
	// resolves to a concrete child session; ChainedRoles is the ref-less fallback.
	if refs := sess.ChainedSessionRefs; len(refs) == 1 {
		marks = append(marks, out+" assumed "+SidForRefShort(refs[0]))
	} else if n := len(refs); n > 1 {
		marks = append(marks, fmt.Sprintf("%s assumed %d roles", out, n))
	} else if n := len(sess.ChainedRoles); n > 0 {
		marks = append(marks, fmt.Sprintf("%s assumed %d roles", out, n))
	}
	if refs := sess.GrantedSessionRefs; len(refs) == 1 {
		marks = append(marks, out+" granted "+SidForRefShort(refs[0]))
	} else if n := len(refs); n > 1 {
		marks = append(marks, fmt.Sprintf("%s granted %d sessions", out, n))
	}

	return strings.Join(marks, "  ")
}
