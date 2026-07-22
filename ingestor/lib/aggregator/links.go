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
)

// link is the in-batch correlation record: a credential/grant issued by a
// resolved person's session. The same records are persisted to
// trailtool-identity-links for cross-batch resolution (read wiring lands with
// the §5 link-layer port).
type link struct {
	kind             linkKind
	personKey        string
	parentSessionRef string // person_key|sk of the issuing/authorizing session
	parentRoleARN    string
	assumedRoleARN   string
	sessionTags      map[string]string
	sessionPolicy    string
	mcpResource      string
	eventTime        string   // grant/AssumeRole event time, for the TTL
	pks              []string // identity-links PKs this link is stored under
}

// candidateLinkKeys returns the identity-link PKs any event in the group could
// match, in match priority order: chain# (this credential was issued by an
// AssumeRole), then mcp# (OAuth token traffic), then login# (aws login vended
// credentials).
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
	for _, e := range g.Events {
		// Only sessionContext marks an event as made under the sign-in session;
		// a grant's own ARN names the session it mints, not its caller's.
		if IsOAuthGrantEvent(e) {
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
// events: AssumeRole chain links and CreateOAuth2Token grants (aws login / MCP).
func registerLinks(links map[string]*link, g identity.Group, person identity.Person, anchor string) {
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

		if IsOAuthGrantEvent(event) {
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
// trailtool-identity-links: the chain/login/mcp links registered during
// resolution, plus a cred# link per tier-1 credential group carrying the
// group's person, role, and anchor (§2.3 — the C1 mitigation and anchor
// continuity for later batches of the same credential).
func writeIdentityLinks(ctx context.Context, ddbClient *dynamodb.Client, table string, resolved []resolvedGroup, links map[string]*link) {
	linkTTL := func(eventTime string) int64 {
		t, err := time.Parse(time.RFC3339, eventTime)
		if err != nil {
			t = time.Now().UTC()
		}
		return t.Add(linkTTLHours * time.Hour).Unix()
	}

	for pk, l := range links {
		rec := &types.DynamoDBIdentityLink{
			PK:               pk,
			PersonKey:        l.personKey,
			ParentSessionRef: l.parentSessionRef,
			ParentRoleARN:    l.parentRoleARN,
			AssumedRoleARN:   l.assumedRoleARN,
			SessionTags:      l.sessionTags,
			SessionPolicy:    l.sessionPolicy,
			MCPResource:      l.mcpResource,
			TTL:              linkTTL(l.eventTime),
		}
		if err := ddblib.WriteIdentityLink(ctx, ddbClient, table, rec); err != nil {
			log.Printf("WARNING: failed to write identity link %s: %v", pk, err)
		}
	}

	for _, rg := range resolved {
		if !rg.ok || rg.person.Tier != identity.TierIdentityCenter {
			continue
		}
		key := rg.group.Key
		if !strings.HasPrefix(key, "ak#") && !strings.HasPrefix(key, "rc#") {
			continue
		}
		first := rg.group.Events[0]
		roleARN := session.GetRoleARN(first)
		if roleARN == "" {
			roleARN = first.UserIdentity.ARN
		}
		rec := &types.DynamoDBIdentityLink{
			PK:        "cred#" + key[3:],
			PersonKey: rg.person.Key,
			RoleARN:   roleARN,
			Anchor:    rg.anchor,
			TTL:       linkTTL(first.EventTime),
		}
		if err := ddblib.WriteIdentityLink(ctx, ddbClient, table, rec); err != nil {
			log.Printf("WARNING: failed to write cred link %s: %v", rec.PK, err)
		}
	}
}
