// Package identity implements TrailTool 1.0 identity resolution: events are
// partitioned into credential groups (all events sharing one credential) and each
// group resolves to at most one person key via a five-tier fallback. Resolution is
// per group, never per event, because not all AWS services log onBehalfOf — one
// human session can mix events with and without it.
package identity

import (
	"strings"

	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// Resolution tiers, in fallback order. A person key's prefix encodes its tier's
// keyspace (idc#, email#, iamuser#, root#), so people can never merge across tiers.
const (
	TierIdentityCenter = 1 // onBehalfOf → Identity Center humans (CLI, console, agents)
	TierLink           = 2 // identity-links lookup → chained roles, aws login, MCP agents
	TierEmail          = 3 // email in role-session name → direct SAML federation
	TierIAMUser        = 4 // long-lived IAM user credentials
	TierRoot           = 5 // root usage
)

// Person is the resolved identity for a credential group.
type Person struct {
	Key  string
	Tier int
}

// Group is one credential group: all events in a batch sharing one credential.
// Key is "" for ungroupable events (no credential, no eventID); such events form
// singleton groups and are never merged with each other.
type Group struct {
	Key    string
	Events []types.CloudTrailRecord
}

// LinkResolver resolves a credential group to a person recorded by an earlier
// batch (tier 2): cred#, chain#, login#, or mcp# records in identity-links-v1.
// It is injected so resolution stays pure; nil means no link layer is available.
type LinkResolver func(g Group) (personKey string, ok bool)

// IdentityCenterPersonKey builds the tier-1 key. It keys on identityStoreArn +
// userId, never userId alone — a userId is only unique within its identity store.
func IdentityCenterPersonKey(identityStoreARN, userID string) string {
	return "idc#" + identityStoreARN + "#" + userID
}

// EmailPersonKey builds the tier-3 key from a role-session-name email.
func EmailPersonKey(email string) string {
	return "email#" + strings.ToLower(email)
}

// IAMUserPersonKey builds the tier-4 key from the IAM user's ARN.
func IAMUserPersonKey(userARN string) string {
	return "iamuser#" + userARN
}

// RootPersonKey builds the tier-5 key from the account ID.
func RootPersonKey(accountID string) string {
	return "root#" + accountID
}

// CredentialGroupKey returns the credential-group key for one event:
//
//	rc#<principalId>#<creationDate>  console sessions — the console mints a fresh access
//	                                 key per request, so the stable creationDate is the
//	                                 credential; keying on the access key would shatter a
//	                                 console session into single-event groups and defeat
//	                                 the any-event-resolves-the-group C1 mitigation.
//	                                 Also the fallback for events with a creationDate but
//	                                 no access key. principalId (roleID:sessionName), not
//	                                 bare roleID: grouping runs before identity, so two
//	                                 humans on the same role in the same second must not
//	                                 share a group.
//	ak#<accessKeyId>                 everything else with an access key (CLI/SDK)
//	ev#<eventID>                     everything else — the event resolves alone
//	""                               ungroupable (no credential and no eventID)
func CredentialGroupKey(event types.CloudTrailRecord) string {
	creationDate := session.GetSessionCreationTime(event)
	if creationDate != "" && (isConsoleSessionCredential(event) || event.UserIdentity.AccessKeyID == "") {
		return "rc#" + event.UserIdentity.PrincipalID + "#" + creationDate
	}
	if ak := event.UserIdentity.AccessKeyID; ak != "" {
		return "ak#" + ak
	}
	if event.EventID != "" {
		return "ev#" + event.EventID
	}
	return ""
}

// isConsoleSessionCredential reports whether the event was made with console session
// credentials, from CloudTrail's own flag (record-level or session-context attribute) —
// deterministic, unlike user-agent classification.
func isConsoleSessionCredential(event types.CloudTrailRecord) bool {
	if event.SessionCredentialFromConsole == "true" {
		return true
	}
	sc := event.UserIdentity.SessionContext
	return sc != nil && sc.Attributes.SessionCredentialFromConsole == "true"
}

// GroupEvents partitions a batch into credential groups, preserving first-seen
// order. Events with an empty key each get their own singleton group.
func GroupEvents(events []types.CloudTrailRecord) []Group {
	var groups []Group
	index := make(map[string]int)
	for _, event := range events {
		key := CredentialGroupKey(event)
		if key == "" {
			groups = append(groups, Group{Events: []types.CloudTrailRecord{event}})
			continue
		}
		if i, ok := index[key]; ok {
			groups[i].Events = append(groups[i].Events, event)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, Group{Key: key, Events: []types.CloudTrailRecord{event}})
	}
	return groups
}

// Anchor resolves the session anchor for a credential group (§3.1): a session is
// the lifetime of a credential or sign-in, so the anchor is derived from fields AWS
// stamps on the events, never from time windows. Like person resolution, the anchor
// is decided per group — signInSessionArn may be stamped per-service (the C1
// discipline applied to session identity). Returns "" when no credential boundary
// exists (long-lived AKIA keys, root, credential-less events): the windowed
// fallback is the caller's job.
//
//	sis#<signInSessionArn>          a literal AWS sign-in session (MCP agents, aws login,
//	                                and AWS's ongoing rollout to ordinary sessions);
//	                                survives credential rotation underneath
//	web#<roleID>#<creationDate>     one console sign-in = one stable creationDate
//	                                across its per-request access keys
//	key#<accessKeyId>               one temporary credential = one session (CLI/SDK,
//	                                chained roles, SAML); a refresh is a new session,
//	                                deliberately
//	""                              windowed fallback (§3.2)
func Anchor(g Group) string {
	for _, event := range g.Events {
		// Only sessionContext.signInSessionArn marks an event as made *under* a
		// sign-in session. A CreateOAuth2Token grant is excluded outright: its ARN
		// (in additionalEventData, and observed in sessionContext too) names the
		// session it mints, not the session the grant was made under — letting it
		// decide the group's anchor would re-key the authorizing human's session.
		if isOAuthGrantEvent(event) {
			continue
		}
		if sc := event.UserIdentity.SessionContext; sc != nil && sc.SignInSessionArn != "" {
			return "sis#" + sc.SignInSessionArn
		}
	}
	for _, event := range g.Events {
		creationDate := session.GetSessionCreationTime(event)
		if creationDate == "" {
			continue
		}
		if isConsoleSessionCredential(event) || event.UserIdentity.AccessKeyID == "" {
			roleID := session.ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)
			return "web#" + roleID + "#" + creationDate
		}
	}
	for _, event := range g.Events {
		if ak := event.UserIdentity.AccessKeyID; strings.HasPrefix(ak, "ASIA") {
			return "key#" + ak
		}
	}
	return ""
}

// isOAuthGrantEvent reports whether the event is a signin.amazonaws.com
// CreateOAuth2Token grant (aws login PKCE or AWS MCP Server token mint).
func isOAuthGrantEvent(event types.CloudTrailRecord) bool {
	return event.EventSource == "signin.amazonaws.com" && event.EventName == "CreateOAuth2Token"
}

// SessionSK builds the trailtool-sessions sort key for an anchored session:
// deterministic, so cross-batch writes for the same credential hit the same item.
func SessionSK(anchor, roleID string) string {
	return anchor + "#" + roleID
}

// WindowSK builds the sort key for a windowed-fallback session (§3.2). The SK is
// sticky — first-written start — so later batches that extend the window earlier
// keep the SK and move the start_time attribute instead.
func WindowSK(roleID, startTime string) string {
	return "win#" + roleID + "#" + startTime
}

// SessionRef names a session record within a customer namespace: person partition
// plus sort key. "|" cannot appear in person keys or anchors, so the ref splits
// unambiguously.
func SessionRef(personKey, sk string) string {
	return personKey + "|" + sk
}

// ResolveGroup resolves one credential group to a person, taking the first tier
// that matches any event in the group. Groups matching no tier (service-internal
// traffic) return false: no person, no session — but the events still feed the
// role/service/resource aggregates.
func ResolveGroup(g Group, links LinkResolver) (Person, bool) {
	for _, event := range g.Events {
		if obo := event.UserIdentity.OnBehalfOf; obo != nil && obo.UserID != "" {
			return Person{
				Key:  IdentityCenterPersonKey(obo.IdentityStoreARN, obo.UserID),
				Tier: TierIdentityCenter,
			}, true
		}
	}

	if links != nil {
		if personKey, ok := links(g); ok && personKey != "" {
			return Person{Key: personKey, Tier: TierLink}, true
		}
	}

	for _, event := range g.Events {
		if email := session.ExtractEmailFromPrincipalID(event.UserIdentity.PrincipalID); email != "" {
			return Person{Key: EmailPersonKey(email), Tier: TierEmail}, true
		}
	}

	for _, event := range g.Events {
		if event.UserIdentity.Type == "IAMUser" && event.UserIdentity.ARN != "" {
			return Person{Key: IAMUserPersonKey(event.UserIdentity.ARN), Tier: TierIAMUser}, true
		}
	}

	for _, event := range g.Events {
		if event.UserIdentity.Type == "Root" {
			accountID := event.UserIdentity.AccountID
			if accountID == "" {
				accountID = event.RecipientAccountID
			}
			if accountID != "" {
				return Person{Key: RootPersonKey(accountID), Tier: TierRoot}, true
			}
		}
	}

	return Person{}, false
}
