// Package aggregator processes CloudTrail events into aggregated entities
// (roles, services, resources, people, sessions, accounts) and writes them
// to DynamoDB.
//
// Sessions are identity-first: events are partitioned into credential groups,
// each group resolves to a person (identity tiers) and a deterministic session
// anchor (sign-in ARN, console creationDate, or the temporary access key itself).
// Time-window guessing survives only as the last-resort fallback for principals
// with no credential boundary (long-lived IAM keys, root).
package aggregator

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/resources"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// linkTTLHours is the STS maximum credential lifetime, used as the TTL for
// identity link records.
const linkTTLHours = 12

// DefaultIdleGap bounds the windowed session fallback: consecutive events
// further apart than this start a new win# session. It applies only to
// principals AWS gives no credential boundary for (long-lived IAM keys, root).
const DefaultIdleGap = 30 * time.Minute

// Session types. Anchored sessions are typed by construction (anchor keyspace
// plus link matches); user-agent classification survives only as the windowed
// fallback's channel label.
const (
	SessionTypeCLI   = "cli"
	SessionTypeWeb   = "web"
	SessionTypeAgent = "agent"
	SessionTypeLogin = "login"
)

// Tables holds the DynamoDB table names for each aggregated entity.
type Tables struct {
	Roles         string
	Services      string
	Resources     string
	People        string
	Sessions      string
	Accounts      string
	IdentityLinks string
}

// Config controls the aggregation behaviour.
type Config struct {
	Tables Tables

	// Namespace is an opaque partition key stored alongside every record.
	// Open-source deployments leave this empty (defaults to "default").
	Namespace string

	// IdleGap overrides DefaultIdleGap for the windowed fallback.
	IdleGap time.Duration
}

func (c Config) namespace() string {
	if c.Namespace != "" {
		return c.Namespace
	}
	return "default"
}

func (c Config) idleGap() time.Duration {
	if c.IdleGap > 0 {
		return c.IdleGap
	}
	return DefaultIdleGap
}

// Process aggregates a batch of CloudTrail events and writes the results to
// DynamoDB. It is the single entry-point for both the open-source and SaaS
// ingestors.
func Process(ctx context.Context, ddbClient *dynamodb.Client, cfg Config, events []types.CloudTrailRecord) error {
	_, err := processInternal(ctx, ddbClient, cfg, events)
	return err
}

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

// resolvedGroup pairs a credential group with its person and session anchor.
type resolvedGroup struct {
	group  identity.Group
	person identity.Person
	ok     bool   // false: no tier matched — no person, no session
	anchor string // "" → windowed fallback
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

// resolveGroups resolves every credential group to a person and anchor,
// iterating so that links registered by resolved groups (an AssumeRole, an
// OAuth grant) can resolve the groups that depend on them — chains within one
// batch resolve regardless of event order. Cross-batch resolution through
// trailtool-identity-links is the §5 link-layer port.
func resolveGroups(groups []identity.Group) ([]resolvedGroup, map[string]*link) {
	links := make(map[string]*link)
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

// anchoredSessionType types an anchored session by construction (§3.1): agent
// requires an mcp# link match — never mere presence of a signInSessionArn, which
// AWS is rolling out to ordinary sessions. login applies to sis#/key# anchors
// only: a web# session matching a login# link is the *authorizing* console
// session (it shares the roleID+creationDate the link is keyed on), not the
// vended one.
func anchoredSessionType(anchor string, mcpL, loginL *link) string {
	if mcpL != nil {
		return SessionTypeAgent
	}
	if strings.HasPrefix(anchor, "web#") {
		return SessionTypeWeb
	}
	if loginL != nil {
		return SessionTypeLogin
	}
	return SessionTypeCLI
}

// newSession initializes a session record for the (person, roleID, anchor) key.
func newSession(ns, personKey, sk, anchor, sessionType, roleARN, roleID, accountID string) *types.DynamoDBSession {
	return &types.DynamoDBSession{
		PK:                      ns + "#" + personKey,
		SK:                      sk,
		CustomerID:              ns,
		PersonKey:               personKey,
		Anchor:                  anchor,
		SessionType:             sessionType,
		RoleARN:                 roleARN,
		RoleID:                  roleID,
		RoleName:                session.ExtractRoleNameFromARN(roleARN),
		AccountID:               accountID,
		RoleKey:                 ns + "#" + roleID,
		AccountKey:              ns + "#" + accountID,
		Version:                 1,
		SourceIPs:               []string{},
		UserAgents:              []string{},
		EventCounts:             make(map[string]int),
		ResourcesAccessed:       make(map[string]int),
		ResourceAccesses:        []types.ResourceAccess{},
		DeniedEventCounts:       make(map[string]int),
		DeniedResourcesAccessed: make(map[string]int),
		DeniedResourceAccesses:  []types.ResourceAccess{},
		DeniedEventAccesses:     []types.EventAccess{},
	}
}

// accumulateSessionEvent folds one event into its session record.
func accumulateSessionEvent(sess *types.DynamoDBSession, event types.CloudTrailRecord, resourceList []string) {
	eventTime := event.EventTime
	if sess.StartTime == "" || eventTime < sess.StartTime {
		sess.StartTime = eventTime
	}
	if eventTime > sess.EndTime {
		sess.EndTime = eventTime
	}

	// Forward-access sessions: an AWS service calling with the human's
	// credentials. Included in the session, counted separately, never ClickOps.
	serviceDriven := event.UserIdentity.InvokedBy != ""
	if serviceDriven {
		sess.ServiceDrivenEventCount++
	}

	isAccessDenied := session.IsAccessDeniedError(event.ErrorCode)
	eventKey := event.EventSource + ":" + event.EventName

	if isAccessDenied {
		policyInfo := session.ExtractPolicyInfo(event.ErrorMessage)
		log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s policy_arn=%s errorMessage=%q",
			sess.SK, eventKey, event.ErrorCode, policyInfo.PolicyARN, event.ErrorMessage)
		sess.DeniedEventCount++
		sess.DeniedEventCounts[eventKey]++

		if len(resourceList) > 0 {
			for _, resource := range resourceList {
				sess.DeniedResourcesAccessed[resource]++
				found := false
				for i := range sess.DeniedResourceAccesses {
					if sess.DeniedResourceAccesses[i].Resource == resource &&
						sess.DeniedResourceAccesses[i].Service == event.EventSource &&
						sess.DeniedResourceAccesses[i].EventName == event.EventName &&
						sess.DeniedResourceAccesses[i].PolicyARN == policyInfo.PolicyARN {
						sess.DeniedResourceAccesses[i].Count++
						found = true
						break
					}
				}
				if !found {
					sess.DeniedResourceAccesses = append(sess.DeniedResourceAccesses, types.ResourceAccess{
						Resource:     resource,
						Service:      event.EventSource,
						EventName:    event.EventName,
						Count:        1,
						PolicyARN:    policyInfo.PolicyARN,
						PolicyType:   policyInfo.PolicyType,
						ErrorMessage: event.ErrorMessage,
					})
				}
			}
		} else {
			found := false
			for i := range sess.DeniedEventAccesses {
				if sess.DeniedEventAccesses[i].Service == event.EventSource &&
					sess.DeniedEventAccesses[i].EventName == event.EventName &&
					sess.DeniedEventAccesses[i].PolicyARN == policyInfo.PolicyARN {
					sess.DeniedEventAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.DeniedEventAccesses = append(sess.DeniedEventAccesses, types.EventAccess{
					Service:      event.EventSource,
					EventName:    event.EventName,
					Count:        1,
					PolicyARN:    policyInfo.PolicyARN,
					PolicyType:   policyInfo.PolicyType,
					ErrorMessage: event.ErrorMessage,
				})
			}
		}
	} else {
		sess.EventsCount++
		sess.EventCounts[eventKey]++
		for _, resource := range resourceList {
			sess.ResourcesAccessed[resource]++
			found := false
			for i := range sess.ResourceAccesses {
				if sess.ResourceAccesses[i].Resource == resource &&
					sess.ResourceAccesses[i].Service == event.EventSource &&
					sess.ResourceAccesses[i].EventName == event.EventName {
					sess.ResourceAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.ResourceAccesses = append(sess.ResourceAccesses, types.ResourceAccess{
					Resource:  resource,
					Service:   event.EventSource,
					EventName: event.EventName,
					Count:     1,
				})
			}
		}
	}

	if !isAccessDenied && !serviceDriven && sess.SessionType == SessionTypeWeb && session.IsClickOpsOperation(event.EventName) {
		sess.ClickOpsEventCount++
		if sess.ClickOpsEventCounts == nil {
			sess.ClickOpsEventCounts = make(map[string]int)
		}
		sess.ClickOpsEventCounts[event.EventName]++
	}

	if sourceIP := event.SourceIPAddress; sourceIP != "" && session.IsValidSourceIP(sourceIP) {
		appendUnique(&sess.SourceIPs, sourceIP)
	}
	if ua := session.NormalizeUserAgent(event.UserAgent); ua != "" && session.IsValidUserAgent(ua) {
		appendUnique(&sess.UserAgents, ua)
	}
	if sess.SignInSessionArn == "" {
		if sc := event.UserIdentity.SessionContext; sc != nil && sc.SignInSessionArn != "" {
			sess.SignInSessionArn = sc.SignInSessionArn
		}
	}
}

// appendUnique appends value to the slice if not already present.
func appendUnique(slice *[]string, value string) {
	for _, v := range *slice {
		if v == value {
			return
		}
	}
	*slice = append(*slice, value)
}

// sessionNameOf returns the role-session-name half of an assumed-role
// principalId ("AROA…:name" → "name"), or "".
func sessionNameOf(principalID string) string {
	if idx := strings.Index(principalID, ":"); idx >= 0 {
		return principalID[idx+1:]
	}
	return ""
}

// processInternal performs aggregation and DynamoDB writes, returning the
// in-memory sessions map keyed by session ref ("person_key|sk"). Extracted for
// testability.
func processInternal(ctx context.Context, ddbClient *dynamodb.Client, cfg Config, events []types.CloudTrailRecord) (map[string]*types.DynamoDBSession, error) {
	ns := cfg.namespace()
	events = dedupeByEventID(events)
	log.Printf("=== Processing Identity-First Aggregation ===")
	log.Printf("Processing %d events for aggregation (namespace: %s)", len(events), ns)

	// Aggregation maps for all nouns
	roles := make(map[string]*types.DynamoDBRole)
	services := make(map[string]*types.DynamoDBService)
	resourceMap := make(map[string]*types.DynamoDBResource)
	people := make(map[string]*types.DynamoDBPerson)
	sessions := make(map[string]*types.DynamoDBSession) // keyed by session ref person_key|sk
	accounts := make(map[string]*types.DynamoDBAccount)

	// Tracking sets for unique counts
	rolePeople := make(map[string]map[string]bool)
	roleSessions := make(map[string]map[string]bool)
	roleAccounts := make(map[string]map[string]bool)
	servicePeople := make(map[string]map[string]bool)
	serviceSessions := make(map[string]map[string]bool)
	serviceAccounts := make(map[string]map[string]bool)
	resourcePeople := make(map[string]map[string]bool)
	resourceSessions := make(map[string]map[string]bool)
	personAccounts := make(map[string]map[string]bool)
	personRoles := make(map[string]map[string]bool)
	personServices := make(map[string]map[string]bool)
	personResources := make(map[string]map[string]bool)
	personSessions := make(map[string]map[string]bool)
	accountPeople := make(map[string]map[string]bool)
	accountSessions := make(map[string]map[string]bool)
	accountRoles := make(map[string]map[string]bool)
	accountServices := make(map[string]map[string]bool)
	accountResources := make(map[string]map[string]bool)
	sessionServices := make(map[string]map[string]bool)
	sessionResources := make(map[string]map[string]bool)

	// Identity resolution: credential groups → person tiers → session anchors,
	// with in-batch chain/login/MCP links resolving tier 2.
	groups := identity.GroupEvents(events)
	resolved, links := resolveGroups(groups)

	// Chaining metadata for parent sessions ingested in a prior invocation:
	// flushed as DynamoDB updates after all current-batch sessions are written.
	type parentUpdate struct {
		parentRef    string
		childRef     string
		childRoleARN string
		eventCount   int
	}
	var deferredParentUpdates []parentUpdate

	for _, rg := range resolved {
		var chainL, loginL, mcpL *link
		var winSlots map[int]windowSlot
		if rg.ok {
			chainL = lookupLinkKind(links, rg.group, linkChain)
			loginL = lookupLinkKind(links, rg.group, linkLogin)
			mcpL = lookupLinkKind(links, rg.group, linkMCP)
			if rg.anchor == "" {
				winSlots = planWindows(rg.group.Events, cfg.idleGap())
			}
		}

		childEvents := 0
		childRef := ""

		for i, event := range rg.group.Events {
			if shouldSkipEvent(event) {
				continue
			}
			eventTime := event.EventTime
			if len(eventTime) < 10 {
				log.Printf("WARNING: skipping event with malformed eventTime %q (%s:%s)", eventTime, event.EventSource, event.EventName)
				continue
			}
			eventDate := eventTime[:10] // YYYY-MM-DD

			personKey := ""
			if rg.ok {
				personKey = rg.person.Key
			}

			// Extract core identifiers
			roleARN := session.GetRoleARN(event)
			if roleARN == "" {
				roleARN = event.UserIdentity.ARN
			}
			// Chained sessions carry the assumed role's IAM ARN from the link,
			// not the sts assumed-role ARN stamped on the events.
			if chainL != nil && chainL.assumedRoleARN != "" {
				roleARN = chainL.assumedRoleARN
			}
			roleID := session.ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)

			// Account ID fallback chain
			accountID := session.ExtractAccountIDFromARN(roleARN)
			if accountID == "" {
				accountID = event.UserIdentity.AccountID
			}
			if accountID == "" && event.UserIdentity.ARN != "" {
				accountID = session.ExtractAccountIDFromARN(event.UserIdentity.ARN)
			}

			resourceList := resources.ExtractResources(event)

			// === Session axis ===
			var sess *types.DynamoDBSession
			sessRef := ""
			if rg.ok {
				sk := ""
				sessionType := ""
				if rg.anchor != "" {
					sk = identity.SessionSK(rg.anchor, roleID)
					sessionType = anchoredSessionType(rg.anchor, mcpL, loginL)
				} else if slot, found := winSlots[i]; found {
					sk = slot.sk
					sessionType = slot.channel
					if mcpL != nil {
						sessionType = SessionTypeAgent
					} else if loginL != nil && sessionType != SessionTypeWeb {
						sessionType = SessionTypeLogin
					}
				}
				if sk != "" {
					sessRef = identity.SessionRef(personKey, sk)
					var exists bool
					sess, exists = sessions[sessRef]
					if !exists {
						anchor := rg.anchor
						if anchor == "" {
							anchor = sk // win# sessions: the sticky window key is the anchor
						}
						sess = newSession(ns, personKey, sk, anchor, sessionType, roleARN, roleID, accountID)
						if chainL != nil {
							sess.AssumedFromSession = chainL.parentSessionRef
							sess.AssumedFromRoleARN = chainL.parentRoleARN
							sess.SessionTags = chainL.sessionTags
							sess.SessionPolicy = chainL.sessionPolicy
						}
						if mcpL != nil {
							sess.MCPResource = mcpL.mcpResource
							sess.AgentAuthorizedBySession = mcpL.parentSessionRef
						}
						if loginL != nil && sessionType == SessionTypeLogin {
							sess.LoginGrantedBySession = loginL.parentSessionRef
						}
						sessions[sessRef] = sess
					}
					accumulateSessionEvent(sess, event, resourceList)
					addToSet(sessionServices, sessRef, event.EventSource)
					if chainL != nil {
						childEvents++
						childRef = sessRef
					}
				}
			}

			if event.ErrorCode != "" {
				log.Printf("EVENT_ERROR: event=%s:%s errorCode=%s person=%s", event.EventSource, event.EventName, event.ErrorCode, personKey)
			}

			// === Person ===
			if rg.ok {
				processPersonEvent(people, rg.person, event, eventDate)
				addToSet(personAccounts, personKey, accountID)
				addToSet(personRoles, personKey, roleARN)
				addToSet(personServices, personKey, event.EventSource)
				addToSet(personSessions, personKey, sessRef)
			}

			// === Account ===
			if accountID != "" {
				processAccountEvent(accounts, accountID, eventDate)
				addToSet(accountPeople, accountID, personKey)
				addToSet(accountSessions, accountID, sessRef)
				addToSet(accountRoles, accountID, roleARN)
				addToSet(accountServices, accountID, event.EventSource)
			}

			// === Role ===
			if roleARN != "" {
				if err := processRoleEvent(roles, event, roleARN, eventDate); err != nil {
					log.Printf("WARNING: Failed to process role event: %v", err)
				}
				addToSet(rolePeople, roleARN, personKey)
				addToSet(roleSessions, roleARN, sessRef)
				addToSet(roleAccounts, roleARN, accountID)
			}

			// === Service ===
			if err := processServiceEvent(services, event, roleARN, eventDate); err != nil {
				log.Printf("WARNING: Failed to process service event: %v", err)
			}
			addToSet(servicePeople, event.EventSource, personKey)
			addToSet(serviceSessions, event.EventSource, sessRef)
			addToSet(serviceAccounts, event.EventSource, accountID)

			// === Resources ===
			for _, resource := range resourceList {
				if err := processResourceEvent(resourceMap, event, resource, accountID, eventDate); err != nil {
					log.Printf("WARNING: Failed to process resource event: %v", err)
				}

				// Track ClickOps operations: console modifications by the human
				// (never service fan-out with the human's credentials).
				if sess != nil && sess.SessionType == SessionTypeWeb &&
					event.UserIdentity.InvokedBy == "" && session.IsClickOpsOperation(event.EventName) {
					if resourceEntry, ok := resourceMap[resource]; ok {
						found := false
						for j := range resourceEntry.ClickOpsAccesses {
							access := &resourceEntry.ClickOpsAccesses[j]
							if access.SessionRef == sessRef && access.EventName == event.EventName {
								access.EventCount++
								found = true
								break
							}
						}
						if !found {
							resourceEntry.ClickOpsAccesses = append(resourceEntry.ClickOpsAccesses, types.ClickOpsAccess{
								SessionRef: sessRef,
								PersonKey:  personKey,
								EventName:  event.EventName,
								AccessTime: sess.StartTime,
								EventCount: 1,
								AccountID:  accountID,
							})
						}
						resourceEntry.ClickOpsCount++
					}
				}

				addToSet(resourcePeople, resource, personKey)
				addToSet(resourceSessions, resource, sessRef)
				if personKey != "" {
					addToSet(personResources, personKey, resource)
				}
				if sessRef != "" {
					addToSet(sessionResources, sessRef, resource)
				}
				if accountID != "" {
					addToSet(accountResources, accountID, resource)
				}
			}
		}

		// Parent bookkeeping for chained child sessions: bump chained counters
		// and register the child ref on the parent session. Same-batch parents
		// update in memory; prior-batch parents get a deferred DynamoDB update.
		if chainL != nil && childRef != "" && childEvents > 0 && chainL.parentSessionRef != "" {
			childRoleARN := chainL.assumedRoleARN
			if parentSess, exists := sessions[chainL.parentSessionRef]; exists {
				parentSess.ChainedEventCount += childEvents
				appendUnique(&parentSess.ChainedRoles, childRoleARN)
				appendUnique(&parentSess.ChainedSessionRefs, childRef)
			} else {
				deferredParentUpdates = append(deferredParentUpdates, parentUpdate{
					parentRef:    chainL.parentSessionRef,
					childRef:     childRef,
					childRoleARN: childRoleARN,
					eventCount:   childEvents,
				})
			}
		}
	}

	// Update counts from unique sets
	for arn, role := range roles {
		role.PeopleCount = setLen(rolePeople, arn)
		role.SessionsCount = setLen(roleSessions, arn)
		role.AccountsCount = setLen(roleAccounts, arn)
	}
	for es, service := range services {
		service.PeopleCount = setLen(servicePeople, es)
		service.SessionsCount = setLen(serviceSessions, es)
		service.AccountsCount = setLen(serviceAccounts, es)
	}
	for rid, resource := range resourceMap {
		resource.PeopleCount = setLen(resourcePeople, rid)
		resource.SessionsCount = setLen(resourceSessions, rid)
	}
	for personKey, person := range people {
		person.AccountsCount = setLen(personAccounts, personKey)
		person.RolesCount = setLen(personRoles, personKey)
		person.ServicesCount = setLen(personServices, personKey)
		person.ResourcesCount = setLen(personResources, personKey)
		person.SessionsCount = setLen(personSessions, personKey)
	}
	for sid, sess := range sessions {
		sess.ServicesCount = setLen(sessionServices, sid)
		sess.ResourcesCount = setLen(sessionResources, sid)
	}
	for aid, account := range accounts {
		account.PeopleCount = setLen(accountPeople, aid)
		account.SessionsCount = setLen(accountSessions, aid)
		account.RolesCount = setLen(accountRoles, aid)
		account.ServicesCount = setLen(accountServices, aid)
		account.ResourcesCount = setLen(accountResources, aid)
	}

	for _, sess := range sessions {
		if sess.StartTime != "" && sess.EndTime != "" {
			startTime, _ := time.Parse(time.RFC3339, sess.StartTime)
			endTime, _ := time.Parse(time.RFC3339, sess.EndTime)
			sess.DurationMinutes = int(endTime.Sub(startTime).Minutes())
		}
	}

	// Log summary
	log.Printf("=== Aggregation Summary ===")
	log.Printf("Found %d unique people, %d sessions, %d roles, %d services, %d resources, %d accounts",
		len(people), len(sessions), len(roles), len(services), len(resourceMap), len(accounts))
	typeCounts := make(map[string]int)
	for _, sess := range sessions {
		typeCounts[sess.SessionType]++
		log.Printf("Session: type=%s person=%s sk=%s role=%s account=%s events=%d start=%s",
			sess.SessionType, sess.PersonKey, sess.SK, sess.RoleName, sess.AccountID, sess.EventsCount, sess.StartTime)
	}
	log.Printf("Session breakdown: cli=%d web=%d agent=%d login=%d",
		typeCounts[SessionTypeCLI], typeCounts[SessionTypeWeb], typeCounts[SessionTypeAgent], typeCounts[SessionTypeLogin])

	// Write aggregated data to DynamoDB (skip when client is nil, e.g. in tests)
	if ddbClient == nil {
		return sessions, nil
	}

	for _, role := range roles {
		role.CustomerID = ns
		if err := ddblib.WriteRoleToDynamoDB(ctx, ddbClient, cfg.Tables.Roles, role); err != nil {
			log.Printf("ERROR: Failed to write role: %v", err)
		}
	}

	for _, service := range services {
		service.CustomerID = ns
		if err := ddblib.WriteServiceToDynamoDB(ctx, ddbClient, cfg.Tables.Services, service); err != nil {
			log.Printf("ERROR: Failed to write service: %v", err)
		}
	}

	for _, resource := range resourceMap {
		resource.CustomerID = ns
		if err := ddblib.WriteResourceToDynamoDB(ctx, ddbClient, cfg.Tables.Resources, resource); err != nil {
			log.Printf("ERROR: Failed to write resource: %v", err)
		}
	}

	for _, person := range people {
		person.CustomerID = ns
		if err := ddblib.WritePersonToDynamoDB(ctx, ddbClient, cfg.Tables.People, person); err != nil {
			log.Printf("ERROR: Failed to write person: %v", err)
		}
	}

	for _, sess := range sessions {
		var err error
		if strings.HasPrefix(sess.SK, "win#") {
			err = ddblib.WriteWindowedSession(ctx, ddbClient, cfg.Tables.Sessions, sess, cfg.idleGap())
		} else {
			err = ddblib.WriteSession(ctx, ddbClient, cfg.Tables.Sessions, sess)
		}
		if err != nil {
			log.Printf("ERROR: Failed to write session %s: %v", sess.SK, err)
		}
	}

	// Persist identity links so later batches can resolve tier 2 and keep anchor
	// continuity (the read side lands with the §5 link-layer port).
	if cfg.Tables.IdentityLinks != "" {
		writeIdentityLinks(ctx, ddbClient, cfg.Tables.IdentityLinks, resolved, links)
	}

	// Flush deferred parent chaining updates (parents ingested in prior batches).
	if len(deferredParentUpdates) > 0 && cfg.Tables.Sessions != "" {
		seen := make(map[string]bool)
		for _, u := range deferredParentUpdates {
			key := u.parentRef + "|" + u.childRef
			if seen[key] {
				continue
			}
			seen[key] = true
			if err := ddblib.UpdateParentSessionChaining(ctx, ddbClient, cfg.Tables.Sessions, ns,
				u.parentRef, u.childRef, u.childRoleARN, u.eventCount); err != nil {
				log.Printf("ERROR: Failed to update parent session chaining: %v", err)
			}
		}
	}

	for _, account := range accounts {
		account.CustomerID = ns
		if err := ddblib.WriteAccountToDynamoDB(ctx, ddbClient, cfg.Tables.Accounts, account); err != nil {
			log.Printf("ERROR: Failed to write account: %v", err)
		}
	}

	log.Printf("Processed %d roles, %d services, %d resources, %d people, %d sessions, %d accounts",
		len(roles), len(services), len(resourceMap), len(people), len(sessions), len(accounts))
	return sessions, nil
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

// addToSet adds value to a nested set map. Skips empty values.
func addToSet(m map[string]map[string]bool, key, value string) {
	if key == "" || value == "" {
		return
	}
	if m[key] == nil {
		m[key] = make(map[string]bool)
	}
	m[key][value] = true
}

// setLen returns the size of a set in the map, or 0 if absent.
func setLen(m map[string]map[string]bool, key string) int {
	if s, ok := m[key]; ok {
		return len(s)
	}
	return 0
}

// processPersonEvent tracks aggregated data for a person. Session names feed
// emails_seen: emails always (lowercased; the first becomes the email_index
// key), non-email names only for tier-1 groups — they're Identity Center
// usernames, whereas chained/link session names are arbitrary strings.
func processPersonEvent(people map[string]*types.DynamoDBPerson, p identity.Person, event types.CloudTrailRecord, eventDate string) {
	person, exists := people[p.Key]
	if !exists {
		person = &types.DynamoDBPerson{
			PersonKey: p.Key,
			Tier:      p.Tier,
			FirstSeen: eventDate,
			LastSeen:  eventDate,
		}
		people[p.Key] = person
	}
	person.LastSeen = eventDate
	person.EventsCount++

	if p.Tier == identity.TierIdentityCenter || p.Tier == identity.TierEmail {
		if name := sessionNameOf(event.UserIdentity.PrincipalID); name != "" {
			if strings.Contains(name, "@") {
				email := strings.ToLower(name)
				if person.Email == "" {
					person.Email = email
				}
				appendUnique(&person.EmailsSeen, email)
			} else if p.Tier == identity.TierIdentityCenter {
				appendUnique(&person.EmailsSeen, name)
			}
		}
	}
}

// processAccountEvent tracks aggregated data for an account.
func processAccountEvent(accounts map[string]*types.DynamoDBAccount, accountID, eventDate string) {
	account, exists := accounts[accountID]
	if !exists {
		account = &types.DynamoDBAccount{
			AccountID: accountID,
			FirstSeen: eventDate,
			LastSeen:  eventDate,
		}
		accounts[accountID] = account
	}
	account.LastSeen = eventDate
	account.EventsCount++
}

// processRoleEvent aggregates an event for a role.
func processRoleEvent(roles map[string]*types.DynamoDBRole, event types.CloudTrailRecord, roleARN string, eventDate string) error {
	role, exists := roles[roleARN]
	if !exists {
		role = &types.DynamoDBRole{
			ARN:                    roleARN,
			Name:                   session.ExtractRoleNameFromARN(roleARN),
			AccountID:              session.ExtractAccountIDFromARN(roleARN),
			FirstSeen:              eventDate,
			LastSeen:               eventDate,
			TotalEvents:            0,
			ServicesCount:          make(map[string]int),
			ResourcesCount:         make(map[string]int),
			TopEventNames:          make(map[string]int),
			ResourceAccesses:       []types.ResourceAccessItem{},
			TotalDeniedEvents:      0,
			TopDeniedEventNames:    make(map[string]int),
			DeniedResourceAccesses: []types.ResourceAccessItem{},
			DeniedEventAccesses:    []types.EventAccessItem{},
		}
		roles[roleARN] = role
	}

	isAccessDenied := session.IsAccessDeniedError(event.ErrorCode)
	eventKey := event.EventSource + ":" + event.EventName

	if isAccessDenied {
		policyInfo := session.ExtractPolicyInfo(event.ErrorMessage)
		if policyInfo.PolicyARN != "" {
			log.Printf("ROLE_ACCESS_DENIED: role=%s event=%s errorCode=%s policy_arn=%s policy_type=%s errorMessage=%q", roleARN, eventKey, event.ErrorCode, policyInfo.PolicyARN, policyInfo.PolicyType, event.ErrorMessage)
		} else {
			log.Printf("ROLE_ACCESS_DENIED: role=%s event=%s errorCode=%s errorMessage=%q", roleARN, eventKey, event.ErrorCode, event.ErrorMessage)
		}

		role.TotalDeniedEvents++
		role.TopDeniedEventNames[eventKey]++

		resourceList := resources.ExtractResources(event)
		if len(resourceList) > 0 {
			for _, resource := range resourceList {
				found := false
				for i := range role.DeniedResourceAccesses {
					ra := &role.DeniedResourceAccesses[i]
					if ra.Resource == resource && ra.EventName == event.EventName && ra.PolicyARN == policyInfo.PolicyARN {
						ra.Count++
						found = true
						break
					}
				}
				if !found {
					parts := strings.Split(resource, ":")
					svc := event.EventSource
					if len(parts) > 0 {
						svc = parts[0] + ".amazonaws.com"
					}
					role.DeniedResourceAccesses = append(role.DeniedResourceAccesses, types.ResourceAccessItem{
						Resource:     resource,
						Service:      svc,
						EventName:    event.EventName,
						Count:        1,
						PolicyARN:    policyInfo.PolicyARN,
						PolicyType:   policyInfo.PolicyType,
						ErrorMessage: event.ErrorMessage,
					})
				}
			}
		} else {
			found := false
			for i := range role.DeniedEventAccesses {
				ea := &role.DeniedEventAccesses[i]
				if ea.Service == event.EventSource && ea.EventName == event.EventName && ea.PolicyARN == policyInfo.PolicyARN {
					ea.Count++
					found = true
					break
				}
			}
			if !found {
				role.DeniedEventAccesses = append(role.DeniedEventAccesses, types.EventAccessItem{
					Service:      event.EventSource,
					EventName:    event.EventName,
					Count:        1,
					PolicyARN:    policyInfo.PolicyARN,
					PolicyType:   policyInfo.PolicyType,
					ErrorMessage: event.ErrorMessage,
				})
			}
		}
	} else {
		role.TotalEvents++
		role.ServicesCount[event.EventSource]++
		role.TopEventNames[eventKey]++

		resourceList := resources.ExtractResources(event)
		for _, resource := range resourceList {
			role.ResourcesCount[resource]++
			found := false
			for i := range role.ResourceAccesses {
				ra := &role.ResourceAccesses[i]
				if ra.Resource == resource && ra.EventName == event.EventName {
					ra.Count++
					found = true
					break
				}
			}
			if !found {
				parts := strings.Split(resource, ":")
				svc := event.EventSource
				if len(parts) > 0 {
					svc = parts[0] + ".amazonaws.com"
				}
				role.ResourceAccesses = append(role.ResourceAccesses, types.ResourceAccessItem{
					Resource:  resource,
					Service:   svc,
					EventName: event.EventName,
					Count:     1,
				})
			}
		}
	}

	role.LastSeen = eventDate
	return nil
}

// processServiceEvent aggregates an event for a service.
func processServiceEvent(serviceMap map[string]*types.DynamoDBService, event types.CloudTrailRecord, roleARN string, eventDate string) error {
	eventSource := event.EventSource
	svc, exists := serviceMap[eventSource]
	if !exists {
		svc = &types.DynamoDBService{
			EventSource:         eventSource,
			DisplayName:         resources.GetServiceDisplayName(eventSource),
			Category:            resources.GetServiceCategory(eventSource),
			FirstSeen:           eventDate,
			LastSeen:            eventDate,
			TotalEvents:         0,
			TopEventNames:       make(map[string]int),
			TotalDeniedEvents:   0,
			TopDeniedEventNames: make(map[string]int),
		}
		serviceMap[eventSource] = svc
	}

	isAccessDenied := session.IsAccessDeniedError(event.ErrorCode)
	if isAccessDenied {
		svc.TotalDeniedEvents++
		svc.TopDeniedEventNames[event.EventName]++
	} else {
		svc.TotalEvents++
		svc.TopEventNames[event.EventName]++
	}

	svc.LastSeen = eventDate

	if roleARN != "" {
		if svc.RolesUsing == nil {
			svc.RolesUsing = []string{}
		}
		appendUnique(&svc.RolesUsing, roleARN)
	}

	return nil
}

// findMatchingCloudTrailResource attempts to match a simplified resource identifier
// with an entry in the CloudTrail Resources array.
func findMatchingCloudTrailResource(event types.CloudTrailRecord, resourceIdentifier string) *types.CloudTrailResource {
	if len(event.Resources) == 0 {
		return nil
	}
	if len(event.Resources) == 1 {
		return &event.Resources[0]
	}

	parts := strings.Split(resourceIdentifier, ":")
	if len(parts) >= 3 {
		resourceName := parts[2]
		for i := range event.Resources {
			if strings.Contains(event.Resources[i].ARN, resourceName) {
				return &event.Resources[i]
			}
		}
	}

	return &event.Resources[0]
}

// processResourceEvent aggregates an event for a resource.
func processResourceEvent(resourceMap map[string]*types.DynamoDBResource, event types.CloudTrailRecord, resourceIdentifier string, accountID string, eventDate string) error {
	resource, exists := resourceMap[resourceIdentifier]
	if !exists {
		parts := strings.Split(resourceIdentifier, ":")
		resourceType := "unknown"
		resourceName := resourceIdentifier

		if len(parts) >= 3 {
			resourceType = parts[0] + ":" + parts[1]
			resourceName = parts[2]
		}

		ctResource := findMatchingCloudTrailResource(event, resourceIdentifier)
		resourceARN := ""
		resourceAccountID := accountID

		if ctResource != nil {
			if ctResource.AccountID != "" {
				resourceAccountID = ctResource.AccountID
			}
			if ctResource.ARN != "" {
				resourceARN = ctResource.ARN
			}
		}

		resource = &types.DynamoDBResource{
			Identifier:          resourceIdentifier,
			Type:                resourceType,
			Name:                resourceName,
			AccountID:           resourceAccountID,
			ARN:                 resourceARN,
			FirstSeen:           eventDate,
			LastSeen:            eventDate,
			TotalEvents:         0,
			TopEventNames:       make(map[string]int),
			TotalDeniedEvents:   0,
			TopDeniedEventNames: make(map[string]int),
		}
		resourceMap[resourceIdentifier] = resource
	}

	isAccessDenied := session.IsAccessDeniedError(event.ErrorCode)
	if isAccessDenied {
		resource.TotalDeniedEvents++
		resource.TopDeniedEventNames[event.EventName]++
	} else {
		resource.TotalEvents++
		resource.TopEventNames[event.EventName]++
	}

	resource.LastSeen = eventDate

	if roleARN := session.GetRoleARN(event); roleARN != "" {
		if resource.RolesUsing == nil {
			resource.RolesUsing = []string{}
		}
		appendUnique(&resource.RolesUsing, roleARN)
	}

	if resource.ServicesUsed == nil {
		resource.ServicesUsed = []string{}
	}
	appendUnique(&resource.ServicesUsed, event.EventSource)

	return nil
}
