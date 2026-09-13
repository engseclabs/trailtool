// Correlation links tie issued credentials, session-creation metadata, and
// OAuth grants back to the relevant person and session. The same records are
// persisted to trailtool-identity-links for cross-batch resolution.
package aggregator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// linkTTLHours is the STS maximum credential lifetime, used as the TTL for
// identity link records.
const linkTTLHours = 12

// linkKind distinguishes the correlation link flavours of the in-batch link map.
type linkKind int

const (
	linkChain    linkKind = iota // AssumeRole issued this credential
	linkLogin                    // aws login (PKCE) vended this credential
	linkMCP                      // AWS MCP Server OAuth token traffic
	linkCred                     // cred# continuity: credential → person + anchor (§2.3)
	linkCreation                 // creation# metadata and resolved session targets
)

// link is the in-batch correlation record: a credential/grant issued by a
// resolved person's session. The same records are persisted to
// trailtool-identity-links; records fetched back from there (stored=true)
// resolve tier 2 and anchor continuity across batches.
type link struct {
	kind              linkKind
	personKey         string
	parentSessionRef  string // person_key|sk of the issuing/authorizing session
	parentRoleARN     string
	assumedRoleARN    string
	sessionTags       map[string]string
	sessionPolicy     string
	hasSessionPolicy  bool
	mcpResource       string
	roleARN           string   // cred# links: the credential group's role
	anchor            string   // cred# links: the anchor decided when first resolved
	targetSessionRefs []string // creation# links: sessions created from this STS response
	eventTime         string   // grant/AssumeRole event time, for the TTL
	stored            bool     // fetched from trailtool-identity-links; not re-written unless re-observed
	observed          bool     // re-observed this batch — refresh its TTL even if stored
	pks               []string // identity-links PKs this link is stored under
}

// credLinkPK maps a credential-group key to its cred# continuity link PK
// ("ak#X" → "cred#X", "rc#Y" → "cred#Y"); "" for ungroupable ev#/empty keys.
func credLinkPK(groupKey string) string {
	if strings.HasPrefix(groupKey, "ak#") || strings.HasPrefix(groupKey, "rc#") {
		return "cred#" + groupKey[3:]
	}
	return ""
}

// creationLinkPKForActivity identifies the STS response that created a
// downstream role session. AWS repeats the response's full assumedRoleId and
// eventTime as the activity event's principalId and creationDate.
func creationLinkPKForActivity(event types.CloudTrailRecord) string {
	if event.UserIdentity.PrincipalID == "" {
		return ""
	}
	creationDate := session.GetSessionCreationTime(event)
	if creationDate == "" {
		return ""
	}
	return "creation#" + event.UserIdentity.PrincipalID + "#" + creationDate
}

// IsAAMAssumeRole reports whether an event is the service-side STS call with
// which AWS Account Access Management creates a role session. These events are
// session-creation metadata, not activity by the resulting human session.
func IsAAMAssumeRole(event types.CloudTrailRecord) bool {
	return event.EventSource == "sts.amazonaws.com" &&
		event.EventName == "AssumeRole" &&
		event.UserIdentity.Type == "AWSService" &&
		event.UserIdentity.InvokedBy == "account-access.amazonaws.com" &&
		ExtractFullAssumedRoleID(event) != ""
}

// creationLinkPKForMetadata identifies the role session created by a metadata
// event that TrailTool does not count as activity. SAML federation and Account
// Access Management have different caller shapes but expose the same join key.
func creationLinkPKForMetadata(event types.CloudTrailRecord) string {
	if event.EventSource != "sts.amazonaws.com" || event.EventTime == "" {
		return ""
	}
	if event.EventName != "AssumeRoleWithSAML" && !IsAAMAssumeRole(event) {
		return ""
	}
	assumedRoleID := ExtractFullAssumedRoleID(event)
	if assumedRoleID == "" {
		return ""
	}
	return "creation#" + assumedRoleID + "#" + event.EventTime
}

// anchorRank orders anchors by cascade strength: a literal sign-in session
// beats a console creationDate beats a bare temporary credential beats the
// windowed fallback. Continuity links only ever move a group UP this order —
// a stronger anchor propagates to weaker groups (a ConsoleLogin bootstrap
// event joins its console session), but a weaker one can never hijack a
// group the cascade already anchored deterministically.
func anchorRank(anchor string) int {
	switch {
	case strings.HasPrefix(anchor, "sis#"):
		return 3
	case strings.HasPrefix(anchor, "web#"):
		return 2
	case strings.HasPrefix(anchor, "key#"):
		return 1
	default:
		return 0
	}
}

// credContinuityPKs returns every cred# link PK that could carry a group's
// credential continuity: the group key itself, each event's access key (a
// sig#-grouped event may carry the stable ASIA key a prior batch anchored —
// the CLI-rollout case), and each event's principalId#creationDate form (which
// per-request-credential events — console bootstrap, forward-access fan-out —
// share with their originating session).
func credContinuityPKs(g identity.Group) []string {
	var pks []string
	seen := make(map[string]bool)
	add := func(pk string) {
		if pk != "" && !seen[pk] {
			seen[pk] = true
			pks = append(pks, pk)
		}
	}
	add(credLinkPK(g.Key))
	for _, e := range g.Events {
		if ak := e.UserIdentity.AccessKeyID; ak != "" {
			add("cred#" + ak)
		}
		if cd := session.GetSessionCreationTime(e); cd != "" && e.UserIdentity.PrincipalID != "" {
			add("cred#" + e.UserIdentity.PrincipalID + "#" + cd)
		}
	}
	return pks
}

// switchRoleBackendUA reports whether a user agent is the AWS Switch-Role
// backend's signature — "AWS Signin, aws-internal/…". This is the only signal
// that distinguishes a console Switch-Role AssumeRole (which must fold into its
// console session) from a genuinely vended credential that merely shares the
// console session's principalId#creationDate (aws login — see
// sameSessionWebAnchor). The Switch-Role backend, not a browser or the CLI,
// emits this UA.
func switchRoleBackendUA(ua string) bool {
	return strings.HasPrefix(session.NormalizeUserAgent(ua), "AWS Signin")
}

// sameSessionWebAnchor returns a web# anchor a cd-keyed continuity link records
// for the group's OWN principalId#creationDate — the console session this
// credential belongs to. It fires only for a console Switch-Role AssumeRole: an
// event carrying the exact principalId#creationDate the web# link is keyed on
// AND the Switch-Role backend UA ("AWS Signin, aws-internal/…").
//
// The principalId#creationDate match alone is NOT enough: aws login vends its
// CLI credential under the authorizing console session's own principalId and
// creationDate (same role, same second), so that guard would wrongly fold the
// vended key# session into the console web# session. The backend-UA requirement
// is what separates the two — the vended credential carries a normal aws-cli UA,
// never "AWS Signin". Returns "" when no such event exists.
func sameSessionWebAnchor(links map[string]*link, g identity.Group) string {
	for _, e := range g.Events {
		if !switchRoleBackendUA(e.UserAgent) {
			continue
		}
		cd := session.GetSessionCreationTime(e)
		if cd == "" || e.UserIdentity.PrincipalID == "" {
			continue
		}
		pk := "cred#" + e.UserIdentity.PrincipalID + "#" + cd
		if l, ok := links[pk]; ok && l.kind == linkCred && strings.HasPrefix(l.anchor, "web#") {
			return l.anchor
		}
	}
	return ""
}

// continuityAnchor applies anchor continuity (§3.1) to a group's cascade
// decision and returns the final anchor:
//
//   - An ak# group's OWN link (cred#<accessKeyId> — the pk embeds the unique
//     credential, so no other credential can have written it) is adopted
//     unconditionally: the anchor decided when this credential first resolved
//     wins, so one credential can never split across two anchors when
//     anchor-deciding fields (signInSessionArn) land only in some batches. The
//     one exception is a console Switch-Role AssumeRole: its backend
//     ("AWS Signin, aws-internal/…") key# credential shares the console
//     session's own principalId#creationDate, so a same-session web# link folds
//     it back into that console session (sameSessionWebAnchor) rather than
//     letting it split off as a phantom key# session that mis-parents the child.
//   - Everything else is rank-guarded — a link may only move the group UP the
//     cascade order. rc# groups share their pk namespace with cd-keyed
//     associative links (cred#<principalId>#<creationDate>), so a console
//     session's deterministic web# anchor can never be hijacked by a key#
//     link some unflagged bootstrap event recorded under the same
//     creationDate; the sis# rollout-safety upgrade still applies.
//   - cd-keyed links reach key#-anchored groups only when the cascade found
//     nothing (forward-access fan-out): a real credential that happens to
//     share a creationDate with another session — aws login vends its
//     credentials with the authorizing session's creationDate — keeps its own
//     key# session.
func continuityAnchor(links map[string]*link, g identity.Group, computed string) string {
	ownPK := credLinkPK(g.Key)
	if strings.HasPrefix(g.Key, "ak#") {
		// A console Switch-Role AssumeRole is a console per-request credential —
		// its principalId#creationDate is the console session's own, so a
		// same-session web# link outranks this credential's split-off key#
		// anchor and reunites them. Guarded to the group's own
		// principalId#creationDate, so a genuinely separate vended credential
		// (agent AssumeRole, aws login) — which carries a different principalId —
		// is never folded and keeps its key# session.
		if web := sameSessionWebAnchor(links, g); web != "" {
			return web
		}
		if l, ok := links[ownPK]; ok && l.kind == linkCred && l.anchor != "" {
			return l.anchor
		}
		if computed != "" {
			return computed // cd-keyed links never re-anchor a keyed credential
		}
	}
	// CLI-rollout continuity: a sig#-grouped event that also carries a stable
	// access key which a prior batch already anchored (cred#<accessKeyId>) stays
	// on that credential's own session, even though this batch's cascade computed
	// sis# — AWS stamping a signInSessionArn onto an established CLI credential
	// (§3.1) must not split it. The cred#<accessKeyId> pk embeds the unique key,
	// so no other credential can have written it; adopt it unconditionally (this
	// is the one sanctioned downgrade below sis#).
	if strings.HasPrefix(g.Key, "sig#") {
		for _, e := range g.Events {
			if ak := e.UserIdentity.AccessKeyID; ak != "" {
				if l, ok := links["cred#"+ak]; ok && l.kind == linkCred && strings.HasPrefix(l.anchor, "key#") {
					return l.anchor
				}
			}
		}
	}
	best := computed
	for _, pk := range credContinuityPKs(g) {
		if l, ok := links[pk]; ok && l.kind == linkCred && anchorRank(l.anchor) > anchorRank(best) {
			best = l.anchor
		}
	}
	return best
}

// candidateIdentityLinkKeys returns only links that can resolve a person or
// session anchor. creation# records are deliberately excluded: they carry
// metadata and target refs, and may exist without a person.
func candidateIdentityLinkKeys(g identity.Group) []string {
	var keys []string
	seen := make(map[string]bool)
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for _, e := range g.Events {
		if ak := e.UserIdentity.AccessKeyID; ak != "" {
			add("chain#" + ak)
		}
		rID := session.ExtractRoleIDFromPrincipalID(e.UserIdentity.PrincipalID)
		st := session.GetSessionCreationTime(e)
		if rID != "" && st != "" {
			add("chain#" + rID + "#" + st)
		}
	}
	for _, pk := range credContinuityPKs(g) {
		add(pk)
	}
	for _, e := range g.Events {
		// Only sessionContext marks an event as made under the sign-in session;
		// a grant's own ARN names the session it mints, not its caller's.
		if identity.IsOAuthGrantEvent(e) {
			continue
		}
		if sc := e.UserIdentity.SessionContext; sc != nil && sc.SignInSessionArn != "" {
			add("mcp#" + sc.SignInSessionArn)
		}
	}
	for _, e := range g.Events {
		rID := session.ExtractRoleIDFromPrincipalID(e.UserIdentity.PrincipalID)
		st := session.GetSessionCreationTime(e)
		if rID != "" && st != "" {
			add("login#" + rID + "#" + st)
		}
	}
	return keys
}

// candidateCreationLinkKeys returns the generic metadata records a group can
// produce or consume. Both sides derive the same key without sharing an access
// key: issuance uses assumedRoleId + eventTime, while activity uses
// principalId + creationDate.
func candidateCreationLinkKeys(g identity.Group) []string {
	var keys []string
	seen := make(map[string]bool)
	for _, event := range g.Events {
		for _, key := range []string{
			creationLinkPKForMetadata(event),
			creationLinkPKForActivity(event),
		} {
			if key != "" && !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	return keys
}

func candidateStoredLinkKeys(g identity.Group) []string {
	keys := candidateIdentityLinkKeys(g)
	return append(keys, candidateCreationLinkKeys(g)...)
}

// linkFromRecord rehydrates a stored identity-link record into the in-batch
// link shape. The kind comes from the PK's keyspace prefix.
func linkFromRecord(pk string, rec *types.DynamoDBIdentityLink) *link {
	l := &link{
		personKey:         rec.PersonKey,
		parentSessionRef:  rec.ParentSessionRef,
		parentRoleARN:     rec.ParentRoleARN,
		assumedRoleARN:    rec.AssumedRoleARN,
		sessionTags:       rec.SessionTags,
		sessionPolicy:     rec.SessionPolicy,
		hasSessionPolicy:  rec.HasSessionPolicy || rec.SessionPolicy != "",
		mcpResource:       rec.MCPResource,
		roleARN:           rec.RoleARN,
		anchor:            rec.Anchor,
		targetSessionRefs: append([]string(nil), rec.TargetSessionRefs...),
		stored:            true,
		pks:               []string{pk},
	}
	switch {
	case strings.HasPrefix(pk, "cred#"):
		l.kind = linkCred
	case strings.HasPrefix(pk, "chain#"):
		l.kind = linkChain
	case strings.HasPrefix(pk, "creation#"):
		l.kind = linkCreation
	case strings.HasPrefix(pk, "login#"):
		l.kind = linkLogin
	case strings.HasPrefix(pk, "mcp#"):
		l.kind = linkMCP
	}
	return l
}

// fetchStoredLinks batch-reads every correlation record the batch's groups
// could match: identity links plus generic creation# records. This is what makes
// tier-2 resolution and anchor continuity work across S3 files: batch A writes
// the links, batch B (same credentials, different file) reads them here.
// Returns nil when no client/table is configured.
func fetchStoredLinks(ctx context.Context, ddbClient *dynamodb.Client, table string, groups []identity.Group) (map[string]*link, error) {
	if ddbClient == nil || table == "" {
		return nil, nil
	}
	var pks []string
	seen := make(map[string]bool)
	for _, g := range groups {
		for _, k := range candidateStoredLinkKeys(g) {
			if !seen[k] {
				seen[k] = true
				pks = append(pks, k)
			}
		}
	}
	if len(pks) == 0 {
		return nil, nil
	}
	recs, err := ddblib.BatchGetIdentityLinks(ctx, ddbClient, table, pks)
	if err != nil {
		return nil, err
	}
	stored := make(map[string]*link, len(recs))
	for pk, rec := range recs {
		stored[pk] = linkFromRecord(pk, rec)
	}
	if len(stored) > 0 {
		log.Printf("IDENTITY_LINKS_FETCHED: %d of %d candidates", len(stored), len(pks))
	}
	return stored, nil
}

func lookupLink(links map[string]*link, g identity.Group) *link {
	for _, k := range candidateIdentityLinkKeys(g) {
		if l, ok := links[k]; ok && l.personKey != "" {
			return l
		}
	}
	return nil
}

func lookupLinkKind(links map[string]*link, g identity.Group, kind linkKind) *link {
	for _, k := range candidateIdentityLinkKeys(g) {
		if l, ok := links[k]; ok && l.kind == kind {
			return l
		}
	}
	return nil
}

// mergeSessionTagMaps combines observed tags without replacing a value already
// attached to the session. A copy is returned so link records and session
// records never share a mutable map.
func mergeSessionTagMaps(existing, incoming map[string]string) map[string]string {
	if len(existing) == 0 && len(incoming) == 0 {
		return nil
	}
	merged := make(map[string]string, len(existing)+len(incoming))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range incoming {
		if _, found := merged[key]; !found {
			merged[key] = value
		}
	}
	return merged
}

// sessionCreationTags returns metadata correlated to a group's downstream
// activity. It is independent of identity resolution.
func sessionCreationTags(links map[string]*link, g identity.Group) map[string]string {
	var tags map[string]string
	for _, key := range candidateCreationLinkKeys(g) {
		if l, ok := links[key]; ok && l.kind == linkCreation {
			tags = mergeSessionTagMaps(tags, l.sessionTags)
		}
	}
	return tags
}

// collectLateSessionTagUpdates applies creation metadata to target sessions in
// this batch and returns updates for sessions written by an earlier batch.
func collectLateSessionTagUpdates(links map[string]*link, sessions map[string]*types.DynamoDBSession) map[string]map[string]string {
	updates := make(map[string]map[string]string)
	for _, l := range links {
		if l.kind != linkCreation || len(l.targetSessionRefs) == 0 || len(l.sessionTags) == 0 {
			continue
		}
		for _, targetRef := range l.targetSessionRefs {
			if sess, ok := sessions[targetRef]; ok {
				sess.SessionTags = mergeSessionTagMaps(sess.SessionTags, l.sessionTags)
				continue
			}
			updates[targetRef] = mergeSessionTagMaps(updates[targetRef], l.sessionTags)
		}
	}
	return updates
}

// registerCreationMetadata records SAML or AAM tags without requiring the
// issuance event to resolve to a person. This is essential for AAM's AWSService
// caller and for SAML events carrying an opaque NameID.
func registerCreationMetadata(links map[string]*link, event types.CloudTrailRecord) {
	pk := creationLinkPKForMetadata(event)
	tags := ExtractSessionTags(event)
	if pk == "" || len(tags) == 0 {
		return
	}
	if existing, ok := links[pk]; ok && existing.kind == linkCreation {
		existing.sessionTags = mergeSessionTagMaps(existing.sessionTags, tags)
		existing.eventTime = event.EventTime
		existing.observed = true
		return
	}
	links[pk] = &link{kind: linkCreation, sessionTags: tags, eventTime: event.EventTime, observed: true, pks: []string{pk}}
	log.Printf("CREATION_METADATA: pk=%s tags=%d", pk, len(tags))
}

func registerCreationMetadataLinks(links map[string]*link, groups []identity.Group) {
	for _, group := range groups {
		for _, event := range group.Events {
			registerCreationMetadata(links, event)
		}
	}
}

// registerCreationTarget records a resolved session as one consumer of the
// STS response. The target list is plural because aws login credentials can
// share principalId + creationDate with their authorizing console session.
func registerCreationTarget(links map[string]*link, event types.CloudTrailRecord, sessionRef string) {
	pk := creationLinkPKForActivity(event)
	if pk == "" || sessionRef == "" {
		return
	}
	l, ok := links[pk]
	if !ok || l.kind != linkCreation {
		l = &link{kind: linkCreation, eventTime: session.GetSessionCreationTime(event), pks: []string{pk}}
		links[pk] = l
	}
	appendUnique(&l.targetSessionRefs, sessionRef)
	l.observed = true
}

// registerLinks records the correlation links contributed by a resolved group's
// events: the group's own cred# continuity links, AssumeRole chain links, and
// CreateOAuth2Token grants (aws login / MCP). Session-creation metadata is
// registered separately because it does not require person resolution.
func registerLinks(links map[string]*link, g identity.Group, person identity.Person, anchor string) {
	// Continuity links for the group's own credential (§2.3, §3.1): map both
	// the credential itself and its principalId#creationDate to the resolved
	// person and anchor. The second form is how forward-access fan-out
	// (invokedBy) — which inherits the originating credential's creationDate
	// but mints per-request access keys — lands in the originating session,
	// in this batch (in-memory) and in later ones (trailtool-identity-links).
	if anchor != "" {
		cl := &link{kind: linkCred, personKey: person.Key, anchor: anchor}
		addPK := func(pk string) {
			for _, existing := range cl.pks {
				if existing == pk {
					return
				}
			}
			cl.pks = append(cl.pks, pk)
		}
		if pk := credLinkPK(g.Key); pk != "" {
			addPK(pk)
		}
		// A sig# group (agent / aws login traffic keyed on its signInSessionArn)
		// must not register principalId#creationDate continuity: it shares that
		// creationDate with the console session that authorized it, and claiming
		// the key would let an agent's sis# anchor hijack the console session —
		// the very cross-contamination the sig# split exists to prevent. Its own
		// cred#<arn> key (added above) is the only continuity it needs.
		if !strings.HasPrefix(g.Key, "sig#") {
			for _, event := range g.Events {
				if event.UserIdentity.InvokedBy != "" {
					continue // fan-out events never define the origin credential
				}
				if cd := session.GetSessionCreationTime(event); cd != "" && event.UserIdentity.PrincipalID != "" {
					addPK("cred#" + event.UserIdentity.PrincipalID + "#" + cd)
				}
			}
		}
		for _, event := range g.Events {
			if event.UserIdentity.InvokedBy != "" {
				continue
			}
			if cl.eventTime == "" {
				cl.eventTime = event.EventTime
			}
			if cl.roleARN == "" {
				cl.roleARN = session.GetRoleARN(event)
			}
		}
		// A stronger anchor replaces a weaker registration for the same
		// credential: the flagged console traffic's web# link must win over
		// the key# link its unflagged ConsoleLogin bootstrap registered.
		for _, pk := range cl.pks {
			cur, exists := links[pk]
			if !exists ||
				(cur.kind == linkCred && anchorRank(cl.anchor) > anchorRank(cur.anchor)) {
				links[pk] = cl
				continue
			}
			// Re-observed at the same (or weaker) rank: the stored link stays,
			// but seeing the credential again this batch must refresh its TTL so
			// active credentials don't expire. Carry the newer event time forward.
			if cur.kind == linkCred {
				cur.observed = true
				if cl.eventTime != "" && cl.eventTime > cur.eventTime {
					cur.eventTime = cl.eventTime
				}
			}
		}
	}

	for _, event := range g.Events {
		roleID := session.ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)
		parentRef := ""
		if anchor != "" && roleID != "" {
			parentRef = identity.SessionRef(person.Key, identity.SessionSK(anchor, roleID))
		}
		parentRoleARN := session.GetRoleARN(event)
		if parentRoleARN == "" {
			parentRoleARN = event.UserIdentity.ARN
		}

		if event.EventName == "AssumeRole" && !IsAAMAssumeRole(event) {
			if strings.Contains(event.UserIdentity.PrincipalID, "ConfigResourceCompositionSession") {
				continue
			}
			issuedKey := ExtractIssuedAccessKeyID(event)
			if issuedKey == "" {
				continue
			}
			l := &link{
				kind:             linkChain,
				personKey:        person.Key,
				parentSessionRef: parentRef,
				parentRoleARN:    parentRoleARN,
				assumedRoleARN:   ExtractAssumedRoleARN(event),
				sessionTags:      ExtractSessionTags(event),
				sessionPolicy:    ExtractSessionPolicy(event),
				hasSessionPolicy: ExtractSessionPolicyPresence(event),
				eventTime:        event.EventTime,
				pks:              []string{"chain#" + issuedKey},
			}
			// Console switch-role variant: the child console session mints a fresh
			// access key per request, so its events are matched by assumed roleID +
			// creationDate (== the AssumeRole event time) instead of the issued key.
			if childRoleID := ExtractAssumedRoleID(event); childRoleID != "" {
				l.pks = append(l.pks, "chain#"+childRoleID+"#"+event.EventTime)
			}
			for _, pk := range l.pks {
				links[pk] = l
			}
			log.Printf("CHAIN_LINK: person=%s parent=%s assumed_role=%s pks=%v",
				person.Key, parentRef, l.assumedRoleARN, l.pks)
		}

		if identity.IsOAuthGrantEvent(event) {
			resource := ExtractOAuthResource(event)
			if IsMCPServerResource(resource) {
				signInSessionArn := ExtractSignInSessionArn(event)
				if signInSessionArn == "" {
					log.Printf("MCP_GRANT_SKIP: CreateOAuth2Token for %s has no signInSessionArn", resource)
					continue
				}
				l := &link{
					kind:             linkMCP,
					personKey:        person.Key,
					parentSessionRef: parentRef,
					parentRoleARN:    parentRoleARN,
					mcpResource:      resource,
					eventTime:        event.EventTime,
					pks:              []string{"mcp#" + signInSessionArn},
				}
				links[l.pks[0]] = l
				log.Printf("MCP_GRANT: signInSessionArn=%s resource=%s authorizedBy=%s", signInSessionArn, resource, parentRef)
			} else {
				st := session.GetSessionCreationTime(event)
				if roleID == "" || st == "" {
					continue
				}
				l := &link{
					kind:             linkLogin,
					personKey:        person.Key,
					parentSessionRef: parentRef,
					parentRoleARN:    parentRoleARN,
					eventTime:        event.EventTime,
					pks:              []string{"login#" + roleID + "#" + st},
				}
				links[l.pks[0]] = l
				log.Printf("LOGIN_GRANT: person=%s roleID=%s startTime=%s parent=%s", person.Key, roleID, st, parentRef)
			}
		}
	}
}

// writeIdentityLinks persists this batch's correlation records to
// trailtool-identity-links: identity/continuity links and generic creation#
// records registered during resolution (§2.3 — the C1 mitigation, anchor
// continuity, and fan-out attribution for later batches).
func writeIdentityLinks(ctx context.Context, ddbClient *dynamodb.Client, table string, links map[string]*link) error {
	linkTTL := func(eventTime string) int64 {
		t, err := time.Parse(time.RFC3339, eventTime)
		if err != nil {
			t = time.Now().UTC()
		}
		return t.Add(linkTTLHours * time.Hour).Unix()
	}

	var writeErrors []error
	for pk, l := range links {
		if l.stored && !l.observed {
			continue // fetched but not re-observed this batch — nothing to record
		}
		rec := &types.DynamoDBIdentityLink{
			PK:                pk,
			PersonKey:         l.personKey,
			ParentSessionRef:  l.parentSessionRef,
			ParentRoleARN:     l.parentRoleARN,
			AssumedRoleARN:    l.assumedRoleARN,
			SessionTags:       l.sessionTags,
			SessionPolicy:     l.sessionPolicy,
			HasSessionPolicy:  l.hasSessionPolicy,
			MCPResource:       l.mcpResource,
			RoleARN:           l.roleARN,
			Anchor:            l.anchor,
			TargetSessionRefs: append([]string(nil), l.targetSessionRefs...),
			TTL:               linkTTL(l.eventTime),
		}
		var err error
		if l.kind == linkCreation {
			err = ddblib.WriteCreationLink(ctx, ddbClient, table, rec)
		} else {
			err = ddblib.WriteIdentityLink(ctx, ddbClient, table, rec)
		}
		if err != nil {
			writeErrors = append(writeErrors, fmt.Errorf("%s: %w", pk, err))
		}
	}
	return errors.Join(writeErrors...)
}
