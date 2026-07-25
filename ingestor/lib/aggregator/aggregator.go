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
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/resources"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// DefaultIdleGap bounds the windowed session fallback: consecutive events
// further apart than this start a new win# session. It applies only to
// principals AWS gives no credential boundary for (long-lived IAM keys, root).
const DefaultIdleGap = 30 * time.Minute

// Tables holds the DynamoDB table names for each aggregated entity.
type Tables struct {
	Roles         string
	Services      string
	Resources     string
	People        string
	Sessions      string
	Accounts      string
	Relations     string
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

// processInternal performs aggregation and DynamoDB writes, returning the
// in-memory sessions map keyed by session ref ("person_key|sk"). Extracted for
// testability.
func processInternal(ctx context.Context, ddbClient *dynamodb.Client, cfg Config, events []types.CloudTrailRecord) (map[string]*types.DynamoDBSession, error) {
	ns := cfg.namespace()
	events = dedupeByEventID(events)
	log.Printf("=== Processing Identity-First Aggregation ===")
	log.Printf("Processing %d events for aggregation (namespace: %s)", len(events), ns)

	// Cross-batch correlation: fetch the identity links earlier batches
	// recorded for this batch's credentials and grants.
	groups := identity.GroupEvents(events)
	stored := fetchStoredLinks(ctx, ddbClient, cfg.Tables.IdentityLinks, groups)
	return aggregateGroups(ctx, ddbClient, cfg, ns, groups, stored)
}

// aggregateGroups resolves the credential groups and aggregates their events
// into entity records, writing to DynamoDB when a client is present. Split
// from processInternal so tests can inject stored links and simulate
// cross-batch delivery.
func aggregateGroups(ctx context.Context, ddbClient *dynamodb.Client, cfg Config, ns string, groups []identity.Group, stored map[string]*link) (map[string]*types.DynamoDBSession, error) {
	// Aggregation maps for all nouns
	roles := make(map[string]*types.DynamoDBRole)
	services := make(map[string]*types.DynamoDBService)
	resourceMap := make(map[string]*types.DynamoDBResource)
	people := make(map[string]*types.DynamoDBPerson)
	sessions := make(map[string]*types.DynamoDBSession) // keyed by session ref person_key|sk
	accounts := make(map[string]*types.DynamoDBAccount)
	relations := make(relationCollector)

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
	// with in-batch and stored chain/login/MCP/cred links resolving tier 2.
	resolved, links := resolveGroups(groups, stored)

	// Chaining metadata for parent sessions ingested in a prior invocation:
	// flushed as DynamoDB updates after all current-batch sessions are written.
	type parentUpdate struct {
		parentRef    string
		childRef     string
		childRoleARN string
		eventCount   int
	}
	var deferredParentUpdates []parentUpdate

	// Grant refs for authorizing sessions ingested in a prior invocation
	// (the symmetric side of aws login / MCP attribution).
	type grantUpdate struct {
		parentRef string
		childRef  string
	}
	var deferredGrantUpdates []grantUpdate

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
						// Grantee-side cross-batch ordering can miss attribution here when
						// the grant's link is persisted after this session was written in an
						// earlier batch — see "Grantee-side cross-batch login/MCP attribution
						// gap" in TODO.md.
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
				processRoleEvent(roles, event, roleARN, eventDate)
				addToSet(rolePeople, roleARN, personKey)
				addToSet(roleSessions, roleARN, sessRef)
				addToSet(roleAccounts, roleARN, accountID)
			}

			// === Service ===
			processServiceEvent(services, event, roleARN, resourceList, eventDate)
			addToSet(servicePeople, event.EventSource, personKey)
			addToSet(serviceSessions, event.EventSource, sessRef)
			addToSet(serviceAccounts, event.EventSource, accountID)

			// === Resources ===
			for _, resource := range resourceList {
				processResourceEvent(resourceMap, event, resource, accountID, eventDate)

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

			recordEventRelations(
				relations,
				ns,
				event.EventTime,
				personKey,
				sessRef,
				accountID,
				roleARN,
				event.EventSource,
				resourceList,
			)
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

	// Symmetric grant refs: record each aws-login/MCP-attributed session on the
	// session that authorized its credentials, mirroring role chaining's
	// parent→child refs so "what did this session authorize?" is answerable
	// from the parent. Same-batch parents update in memory; prior-batch parents
	// get a deferred DynamoDB update.
	for sessRef, sess := range sessions {
		for _, grantRef := range []string{sess.AgentAuthorizedBySession, sess.LoginGrantedBySession} {
			if grantRef == "" || grantRef == sessRef {
				continue
			}
			if parentSess, inBatch := sessions[grantRef]; inBatch {
				appendUnique(&parentSess.GrantedSessionRefs, sessRef)
			} else {
				deferredGrantUpdates = append(deferredGrantUpdates, grantUpdate{parentRef: grantRef, childRef: sessRef})
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
		sess.Sid = identity.Sid(sess.PersonKey, sess.SK)
		if strings.HasPrefix(sess.SK, "win#") {
			var persisted *types.DynamoDBSession
			persisted, err = ddblib.WriteWindowedSessionResolved(ctx, ddbClient, cfg.Tables.Sessions, sess, cfg.idleGap())
			if err == nil {
				oldRef := identity.SessionRef(sess.PersonKey, sess.SK)
				newRef := identity.SessionRef(persisted.PersonKey, persisted.SK)
				relations.replaceID(ddblib.RelationKindSession, oldRef, newRef)
			}
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
		writeIdentityLinks(ctx, ddbClient, cfg.Tables.IdentityLinks, links)
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

	// Flush deferred grant refs (authorizing sessions from prior batches).
	if len(deferredGrantUpdates) > 0 && cfg.Tables.Sessions != "" {
		seen := make(map[string]bool)
		for _, u := range deferredGrantUpdates {
			key := u.parentRef + "|" + u.childRef
			if seen[key] {
				continue
			}
			seen[key] = true
			if err := ddblib.UpdateParentSessionGrants(ctx, ddbClient, cfg.Tables.Sessions, ns,
				u.parentRef, u.childRef); err != nil {
				log.Printf("ERROR: Failed to update authorizing session grants: %v", err)
			}
		}
	}

	for _, account := range accounts {
		account.CustomerID = ns
		if err := ddblib.WriteAccountToDynamoDB(ctx, ddbClient, cfg.Tables.Accounts, account); err != nil {
			log.Printf("ERROR: Failed to write account: %v", err)
		}
	}

	if cfg.Tables.Relations != "" {
		if err := ddblib.WriteRelations(ctx, ddbClient, cfg.Tables.Relations, relations.edges()); err != nil {
			return sessions, fmt.Errorf("write noun relations: %w", err)
		}
	}

	log.Printf("Processed %d roles, %d services, %d resources, %d people, %d sessions, %d accounts, %d relation edges",
		len(roles), len(services), len(resourceMap), len(people), len(sessions), len(accounts), len(relations))
	return sessions, nil
}
