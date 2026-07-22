// Correlation links: the in-batch registry tying issued credentials and
// OAuth grants (AssumeRole chains, aws login, AWS MCP Server) back to the
// person and session that created them, plus persistence of the same
// records to trailtool-identity-links for cross-batch resolution.
package aggregator

import (
	"context"
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
	linkChain linkKind = iota // AssumeRole issued this credential
	linkLogin                 // aws login (PKCE) vended this credential
	linkMCP                   // AWS MCP Server OAuth token traffic
	linkCred                  // cred# continuity: credential → person + anchor (§2.3)
)

// link is the in-batch correlation record: a credential/grant issued by a
// resolved person's session. The same records are persisted to
// trailtool-identity-links; records fetched back from there (stored=true)
// resolve tier 2 and anchor continuity across batches.
type link struct {
	kind             linkKind
	personKey        string
	parentSessionRef string // person_key|sk of the issuing/authorizing session
	parentRoleARN    string
	assumedRoleARN   string
	sessionTags      map[string]string
	sessionPolicy    string
	mcpResource      string
	roleARN          string   // cred# links: the credential group's role
	anchor           string   // cred# links: the anchor decided when first resolved
	eventTime        string   // grant/AssumeRole event time, for the TTL
	stored           bool     // fetched from trailtool-identity-links; not re-written unless re-observed
	observed         bool     // re-observed this batch — refresh its TTL even if stored
	pks              []string // identity-links PKs this link is stored under
}

// credLinkPK maps a credential-group key to its cred# continuity link PK
// ("ak#X" → "cred#X", "rc#Y" → "cred#Y"); "" for ungroupable ev#/empty keys.
func credLinkPK(groupKey string) string {
	if strings.HasPrefix(groupKey, "ak#") || strings.HasPrefix(groupKey, "rc#") {
		return "cred#" + groupKey[3:]
	}
	return ""
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

// continuityAnchor applies anchor continuity (§3.1) to a group's cascade
// decision and returns the final anchor:
//
//   - An ak# group's OWN link (cred#<accessKeyId> — the pk embeds the unique
//     credential, so no other credential can have written it) is adopted
//     unconditionally: the anchor decided when this credential first resolved
//     wins, so one credential can never split across two anchors when
//     anchor-deciding fields (signInSessionArn) land only in some batches.
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

// candidateLinkKeys returns the identity-link PKs any event in the group could
// match, in match priority order: chain# (this credential was issued by an
// AssumeRole), then the group's own cred# continuity key, then mcp# (OAuth
// token traffic), then login# (aws login vended credentials).
func candidateLinkKeys(g identity.Group) []string {
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

// linkFromRecord rehydrates a stored identity-link record into the in-batch
// link shape. The kind comes from the PK's keyspace prefix.
func linkFromRecord(pk string, rec *types.DynamoDBIdentityLink) *link {
	l := &link{
		personKey:        rec.PersonKey,
		parentSessionRef: rec.ParentSessionRef,
		parentRoleARN:    rec.ParentRoleARN,
		assumedRoleARN:   rec.AssumedRoleARN,
		sessionTags:      rec.SessionTags,
		sessionPolicy:    rec.SessionPolicy,
		mcpResource:      rec.MCPResource,
		roleARN:          rec.RoleARN,
		anchor:           rec.Anchor,
		stored:           true,
		pks:              []string{pk},
	}
	switch {
	case strings.HasPrefix(pk, "cred#"):
		l.kind = linkCred
	case strings.HasPrefix(pk, "chain#"):
		l.kind = linkChain
	case strings.HasPrefix(pk, "login#"):
		l.kind = linkLogin
	case strings.HasPrefix(pk, "mcp#"):
		l.kind = linkMCP
	}
	return l
}

// fetchStoredLinks batch-reads every identity-link record the batch's groups
// could match — the groups' own cred# continuity keys plus the
// chain#/login#/mcp# candidates their events reference. This is what makes
// tier-2 resolution and anchor continuity work across S3 files: batch A writes
// the links, batch B (same credentials, different file) reads them here.
// Returns nil when no client/table is configured.
func fetchStoredLinks(ctx context.Context, ddbClient *dynamodb.Client, table string, groups []identity.Group) map[string]*link {
	if ddbClient == nil || table == "" {
		return nil
	}
	var pks []string
	seen := make(map[string]bool)
	for _, g := range groups {
		for _, k := range candidateLinkKeys(g) {
			if !seen[k] {
				seen[k] = true
				pks = append(pks, k)
			}
		}
	}
	if len(pks) == 0 {
		return nil
	}
	recs, err := ddblib.BatchGetIdentityLinks(ctx, ddbClient, table, pks)
	if err != nil {
		log.Printf("WARNING: batch get identity links failed: %v", err)
		return nil
	}
	stored := make(map[string]*link, len(recs))
	for pk, rec := range recs {
		stored[pk] = linkFromRecord(pk, rec)
	}
	if len(stored) > 0 {
		log.Printf("IDENTITY_LINKS_FETCHED: %d of %d candidates", len(stored), len(pks))
	}
	return stored
}

func lookupLink(links map[string]*link, g identity.Group) *link {
	for _, k := range candidateLinkKeys(g) {
		if l, ok := links[k]; ok {
			return l
		}
	}
	return nil
}

func lookupLinkKind(links map[string]*link, g identity.Group, kind linkKind) *link {
	for _, k := range candidateLinkKeys(g) {
		if l, ok := links[k]; ok && l.kind == kind {
			return l
		}
	}
	return nil
}

// registerLinks records the correlation links contributed by a resolved group's
// events: the group's own cred# continuity links, AssumeRole chain links, and
// CreateOAuth2Token grants (aws login / MCP).
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

		if event.EventName == "AssumeRole" {
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
// trailtool-identity-links: the cred# continuity links and chain/login/mcp
// links registered during resolution (§2.3 — the C1 mitigation, anchor
// continuity, and fan-out attribution for later batches).
func writeIdentityLinks(ctx context.Context, ddbClient *dynamodb.Client, table string, links map[string]*link) {
	linkTTL := func(eventTime string) int64 {
		t, err := time.Parse(time.RFC3339, eventTime)
		if err != nil {
			t = time.Now().UTC()
		}
		return t.Add(linkTTLHours * time.Hour).Unix()
	}

	for pk, l := range links {
		if l.stored && !l.observed {
			continue // fetched but not re-observed this batch — nothing to record
		}
		rec := &types.DynamoDBIdentityLink{
			PK:               pk,
			PersonKey:        l.personKey,
			ParentSessionRef: l.parentSessionRef,
			ParentRoleARN:    l.parentRoleARN,
			AssumedRoleARN:   l.assumedRoleARN,
			SessionTags:      l.sessionTags,
			SessionPolicy:    l.sessionPolicy,
			MCPResource:      l.mcpResource,
			RoleARN:          l.roleARN,
			Anchor:           l.anchor,
			TTL:              linkTTL(l.eventTime),
		}
		if err := ddblib.WriteIdentityLink(ctx, ddbClient, table, rec); err != nil {
			log.Printf("WARNING: failed to write identity link %s: %v", pk, err)
		}
	}
}
