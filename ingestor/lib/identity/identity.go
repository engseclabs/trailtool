// Package identity implements TrailTool 1.0 identity resolution: events are
// partitioned into credential groups (all events sharing one credential) and each
// group resolves to at most one person key via a five-tier fallback. Resolution is
// per group, never per event, because not all AWS services log onBehalfOf — one
// human session can mix events with and without it.
package identity

import (
	"crypto/sha256"
	"encoding/base32"
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
//	sig#<signInSessionArn>           events made *under* a sign-in session (agent /
//	                                 aws login traffic): the arn is the credential
//	                                 boundary, checked first as the strongest and most
//	                                 specific. Without this, agent traffic sharing a
//	                                 console creationDate — and rotating a fresh access
//	                                 key per request — would either fall into the console
//	                                 rc# group or shatter across ak# groups, mixing the
//	                                 human console session and one or more agent sessions.
//	                                 The CLI-rollout case (a stable CLI credential that
//	                                 also gets stamped with a signInSessionArn, §3.1) is
//	                                 preserved by anchor continuity: its cross-batch
//	                                 cred#<accessKeyId> link, keyed on the stable ASIA key
//	                                 rather than the arn, still carries its key# anchor
//	                                 forward (see continuityAnchor). Excludes the
//	                                 CreateOAuth2Token grant, whose arn (in
//	                                 additionalEventData) names the session it mints, not
//	                                 the one it was made under.
//	rc#<principalId>#<creationDate>  per-request-credential sessions: the console AND
//	                                 forward-access sessions (invokedBy — CloudFormation
//	                                 fan-out etc.) mint a fresh access key per request,
//	                                 so the stable creationDate is the credential; keying
//	                                 on the access key would shatter one session into
//	                                 single-event groups and defeat the
//	                                 any-event-resolves-the-group C1 mitigation.
//	                                 Also the fallback for events with a creationDate but
//	                                 no access key. principalId (roleID:sessionName), not
//	                                 bare roleID: grouping runs before identity, so two
//	                                 humans on the same role in the same second must not
//	                                 share a group.
//	ak#<accessKeyId>                 everything else with an access key (CLI/SDK)
//	ev#<eventID>                     everything else — the event resolves alone
//	""                               ungroupable (no credential and no eventID)
func CredentialGroupKey(event types.CloudTrailRecord) string {
	if !isOAuthGrantEvent(event) {
		if sc := event.UserIdentity.SessionContext; sc != nil && sc.SignInSessionArn != "" {
			return "sig#" + sc.SignInSessionArn
		}
	}
	creationDate := session.GetSessionCreationTime(event)
	if creationDate != "" && (isConsoleSessionCredential(event) ||
		event.UserIdentity.AccessKeyID == "" ||
		event.UserIdentity.InvokedBy != "") {
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

// isConsoleSessionCredential reports whether the event was made with console
// session credentials: CloudTrail's own flag (record-level or session-context
// attribute), or — the §10 sanctioned fallback — a browser user agent. The
// fallback exists because the flag is not stamped on every console-session
// event: sign-in bootstrap events (ConsoleLogin, GetSigninToken) and some
// console framework calls carry a browser UA and the session's creationDate
// but no flag, and must not shatter into per-key sessions.
func isConsoleSessionCredential(event types.CloudTrailRecord) bool {
	if event.SessionCredentialFromConsole == "true" {
		return true
	}
	if sc := event.UserIdentity.SessionContext; sc != nil && sc.Attributes.SessionCredentialFromConsole == "true" {
		return true
	}
	return session.ClassifySessionType(session.NormalizeUserAgent(event.UserAgent)) == "web-console"
}

// GroupEvents partitions a batch into credential groups, preserving first-seen
// order. Events with an empty key each get their own singleton group.
func GroupEvents(events []types.CloudTrailRecord) []Group {
	var groups []Group
	index := make(map[string]int)
	// console groups this batch, indexed by principalId, so a bare console
	// sign-in event (which has no credential fields of its own) can be folded
	// into the console session it initiates — see foldConsoleSignIn.
	consoleByPrincipal := make(map[string]int)
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
		if strings.HasPrefix(key, "rc#") && isConsoleSessionCredential(event) {
			consoleByPrincipal[event.UserIdentity.PrincipalID] = len(groups)
		}
		groups = append(groups, Group{Key: key, Events: []types.CloudTrailRecord{event}})
	}
	return foldConsoleSignIn(groups, consoleByPrincipal)
}

// isConsoleSignInEvent reports whether the event is a console sign-in
// (ConsoleLogin / AwsConsoleSignIn from signin.amazonaws.com). AWS stamps these
// with a bare userIdentity — principalId and arn, but no sessionContext — so
// they carry no creationDate, access key, or sessionCredentialFromConsole flag,
// and can neither group into nor anchor onto the console session they open.
func isConsoleSignInEvent(event types.CloudTrailRecord) bool {
	return event.EventSource == "signin.amazonaws.com" &&
		(event.EventName == "ConsoleLogin" || event.EventType == "AwsConsoleSignIn")
}

// foldConsoleSignIn moves a bare console sign-in event out of its ev#/singleton
// group into the console session it initiated — the rc# console group sharing
// its principalId — so the sign-in joins that web# session instead of falling
// to the windowed fallback as a spurious one-event session. If no matching
// console group exists in the batch (the sign-in's activity landed in another
// file), the event stays in its own group and resolves normally.
func foldConsoleSignIn(groups []Group, consoleByPrincipal map[string]int) []Group {
	drop := make(map[int]bool)
	for gi := range groups {
		if len(groups[gi].Events) != 1 {
			continue
		}
		e := groups[gi].Events[0]
		if !isConsoleSignInEvent(e) {
			continue
		}
		target, ok := consoleByPrincipal[e.UserIdentity.PrincipalID]
		if !ok || target == gi {
			continue
		}
		groups[target].Events = append(groups[target].Events, e)
		drop[gi] = true
	}
	if len(drop) == 0 {
		return groups
	}
	out := groups[:0:0]
	for gi := range groups {
		if !drop[gi] {
			out = append(out, groups[gi])
		}
	}
	return out
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
		// A forward-access session's keys are per-request vends, not a session
		// credential — they must never mint a key# anchor. The group instead
		// adopts the originating session's anchor through its
		// cred#<principalId>#<creationDate> continuity link (forward-access
		// sessions inherit the originator's creationDate).
		if event.UserIdentity.InvokedBy != "" {
			continue
		}
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

// SidLength is the number of base32 characters in a stored session id. 16 chars =
// 80 bits: collision-free across any realistic dataset. Users never type the whole
// thing — the CLI shows and accepts a short prefix (see SidDisplayMin) and resolves
// it against the sid_index GSI with begins_with, Git-style. Storing full strength
// keeps that prefix resolution safe as datasets grow.
const SidLength = 16

// SidDisplayMin is the shortest prefix the CLI shows by default; it widens per
// list only when two rows would otherwise share a prefix.
const SidDisplayMin = 6

// Sid derives a deterministic, typable id for a session from its ref
// (person_key|sk). It is the sort key of the sessions sid_index GSI (partition key
// customerId), so "--session <prefix>" resolves via a single begins_with Query.
// Deterministic means merges and re-ingests keep the same sid; lowercase base32
// avoids shell-quoting and visually ambiguous characters.
func Sid(personKey, sk string) string {
	sum := sha256.Sum256([]byte(SessionRef(personKey, sk)))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return strings.ToLower(enc[:SidLength])
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
