// Credential-group resolution: partitioning a batch into groups, resolving
// each to a person and session anchor (iterating so in-batch links can
// satisfy tier 2), batch hygiene (eventID dedupe, bookkeeping-event skips),
// and idle-gap window planning for anchor-less groups.
package aggregator

import (
	"log"
	"sort"
	"strings"
	"time"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// resolvedGroup pairs a credential group with its person and session anchor.
type resolvedGroup struct {
	group  identity.Group
	person identity.Person
	ok     bool   // false: no tier matched — no person, no session
	anchor string // "" → windowed fallback
}

// resolveGroups resolves every credential group to a person and anchor,
// iterating so that links registered by resolved groups (an AssumeRole, an
// OAuth grant) can resolve the groups that depend on them — chains within one
// batch resolve regardless of event order. The stored map seeds the link
// registry with records fetched from trailtool-identity-links, so tier 2 and
// anchor continuity also work across batches (S3 files).
func resolveGroups(groups []identity.Group, stored map[string]*link) ([]resolvedGroup, map[string]*link) {
	links := make(map[string]*link, len(stored))
	for pk, l := range stored {
		links[pk] = l
	}
	resolved := make([]resolvedGroup, len(groups))

	resolver := func(g identity.Group) (string, bool) {
		if l := lookupLink(links, g); l != nil {
			return l.personKey, true
		}
		return "", false
	}

	pending := make([]int, 0, len(groups))
	for i := range groups {
		pending = append(pending, i)
	}
	for len(pending) > 0 {
		progress := false
		var still []int
		for _, i := range pending {
			person, ok := identity.ResolveGroup(groups[i], resolver)
			if !ok {
				still = append(still, i)
				continue
			}
			anchor := identity.Anchor(groups[i])
			// Anchor continuity (§3.1): the anchor decided when the credential
			// first resolved wins, so a credential can never split across two
			// anchors when anchor-deciding fields (signInSessionArn) are
			// stamped per-service or land only in some batches.
			if pk := credLinkPK(groups[i].Key); pk != "" {
				if l, found := links[pk]; found && l.kind == linkCred && l.anchor != "" {
					anchor = l.anchor
				}
			}
			resolved[i] = resolvedGroup{group: groups[i], person: person, ok: true, anchor: anchor}
			registerLinks(links, groups[i], person, anchor)
			progress = true
		}
		pending = still
		if !progress {
			break
		}
	}
	for _, i := range pending {
		resolved[i] = resolvedGroup{group: groups[i]}
	}
	return resolved, links
}

// dedupeByEventID drops repeated eventIDs within a batch: org trails duplicate
// global-service events across region files. Events without an eventID pass
// through untouched. Cross-file duplicates are accepted (rare; bounded error).
func dedupeByEventID(events []types.CloudTrailRecord) []types.CloudTrailRecord {
	seen := make(map[string]bool, len(events))
	out := make([]types.CloudTrailRecord, 0, len(events))
	dropped := 0
	for _, e := range events {
		if e.EventID != "" {
			if seen[e.EventID] {
				dropped++
				continue
			}
			seen[e.EventID] = true
		}
		out = append(out, e)
	}
	if dropped > 0 {
		log.Printf("DEDUPE: dropped %d duplicate eventIDs within batch", dropped)
	}
	return out
}

// shouldSkipEvent filters console/OAuth bookkeeping that would otherwise create
// spurious sessions or inflate counts: SwitchRole signin events, CreateOAuth2Token
// grants (consumed by the link layer), and AWS Config's synthetic sessions.
func shouldSkipEvent(event types.CloudTrailRecord) bool {
	if strings.Contains(event.UserIdentity.PrincipalID, "ConfigResourceCompositionSession") {
		return true
	}
	if event.EventSource == "signin.amazonaws.com" &&
		(event.EventName == "SwitchRole" || event.EventName == "CreateOAuth2Token") {
		return true
	}
	return false
}

// windowSlot assigns one event of an anchor-less group to a win# session.
type windowSlot struct {
	sk      string
	channel string // cli | web — display channel from user-agent classification
}

// planWindows splits an anchor-less group's events into idle-gap windows per
// (roleID, channel): a maximal run of events with consecutive gaps ≤ idleGap.
// Returns the win# sort key per event index.
func planWindows(events []types.CloudTrailRecord, idleGap time.Duration) map[int]windowSlot {
	slots := make(map[int]windowSlot)
	lanes := make(map[string][]int)
	channels := make(map[string]string)
	roleIDs := make(map[string]string)
	for i, e := range events {
		if shouldSkipEvent(e) {
			continue
		}
		roleID := session.ExtractRoleIDFromPrincipalID(e.UserIdentity.PrincipalID)
		channel := SessionTypeCLI
		if session.ClassifySessionType(session.NormalizeUserAgent(e.UserAgent)) == "web-console" {
			channel = SessionTypeWeb
		}
		lane := roleID + "|" + channel
		lanes[lane] = append(lanes[lane], i)
		channels[lane] = channel
		roleIDs[lane] = roleID
	}
	for lane, idxs := range lanes {
		sort.Slice(idxs, func(a, b int) bool { return events[idxs[a]].EventTime < events[idxs[b]].EventTime })
		var prev time.Time
		runStart := ""
		for _, i := range idxs {
			t, err := time.Parse(time.RFC3339, events[i].EventTime)
			if err == nil && (runStart == "" || t.Sub(prev) > idleGap) {
				runStart = events[i].EventTime
			}
			if err == nil {
				prev = t
			}
			if runStart == "" { // unparsable time before any run started
				runStart = events[i].EventTime
			}
			slots[i] = windowSlot{sk: identity.WindowSK(roleIDs[lane], runStart), channel: channels[lane]}
		}
	}
	return slots
}
