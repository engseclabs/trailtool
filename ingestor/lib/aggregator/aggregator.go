// Package aggregator processes CloudTrail events into aggregated entities
// (roles, services, resources, people, sessions, accounts) and writes them
// to DynamoDB.
package aggregator

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/resources"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// chainLinkTTLHours is the STS maximum credential lifetime used as the TTL for chain link records.
const chainLinkTTLHours = 12

// Tables holds the DynamoDB table names for each aggregated entity.
type Tables struct {
	Roles      string
	Services   string
	Resources  string
	People     string
	Sessions   string
	Accounts   string
	ChainLinks string
}

// Config controls the aggregation behaviour.
type Config struct {
	Tables Tables

	// Namespace is an opaque partition key stored alongside every record.
	// Open-source deployments leave this empty (defaults to "default").
	Namespace string
}

func (c Config) namespace() string {
	if c.Namespace != "" {
		return c.Namespace
	}
	return "default"
}

// Process aggregates a batch of CloudTrail events and writes the results to
// DynamoDB. It is the single entry-point for both the open-source and SaaS
// ingestors.
func Process(ctx context.Context, ddbClient *dynamodb.Client, cfg Config, events []types.CloudTrailRecord) error {
	_, err := processInternal(ctx, ddbClient, cfg, events)
	return err
}

// processInternal performs aggregation and DynamoDB writes, returning the
// in-memory sessions map. Extracted for testability.
func processInternal(ctx context.Context, ddbClient *dynamodb.Client, cfg Config, events []types.CloudTrailRecord) (map[string]*types.DynamoDBSessionAggregated, error) {
	ns := cfg.namespace()
	log.Printf("=== Processing Noun-Based Aggregation ===")
	log.Printf("Processing %d events for aggregation (namespace: %s)", len(events), ns)

	// Aggregation maps for all nouns
	roles := make(map[string]*types.DynamoDBRole)
	services := make(map[string]*types.DynamoDBService)
	resourceMap := make(map[string]*types.DynamoDBResource)
	people := make(map[string]*types.DynamoDBPerson)
	sessions := make(map[string]*types.DynamoDBSessionAggregated)
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

	// === Pass 1: Discover AssumeRole events from known sessions ===
	// Build a map of issued access key IDs → parent session map keys for this batch.
	// Also write chain link records to DynamoDB so cross-file chains work in future batches.
	newChainLinks := make(map[string]*types.DynamoDBChainLink) // issuedKeyID -> chain link

	// deferredParentUpdates holds chaining metadata for parent sessions that are NOT in the
	// current in-memory sessions map (i.e. ingested in a prior Lambda invocation).
	// We flush these to DynamoDB after writing all current-batch sessions so that a
	// same-batch parent is fully written before we try to update it.
	type parentUpdate struct {
		parentSessionMapKey string
		childSessionMapKey  string
		childRoleARN        string
	}
	var deferredParentUpdates []parentUpdate

	for _, event := range events {
		if event.EventName != "AssumeRole" {
			continue
		}
		if strings.Contains(event.UserIdentity.PrincipalID, "ConfigResourceCompositionSession") {
			continue
		}

		email := session.ExtractEmailFromPrincipalID(event.UserIdentity.PrincipalID)
		if email == "" {
			continue // only attribute human-initiated AssumeRole
		}

		issuedKeyID := ExtractIssuedAccessKeyID(event)
		if issuedKeyID == "" {
			continue
		}

		assumedRoleARN := ExtractAssumedRoleARN(event)
		roleID := session.ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)
		roleARN := session.GetRoleARN(event)
		if roleARN == "" {
			roleARN = event.UserIdentity.ARN
		}

		// Build the parent session map key.
		// For the AssumeRole event itself we always prefer the IAM session creation time
		// from sessionContext — this matches how the parent session was keyed in Pass 2
		// regardless of whether it was a console or CLI session.
		// We only fall back to CLI 4-hour windowing when no creation time is available.
		var parentSessionMapKey string
		if email != "" && roleID != "" {
			creationTime := session.GetSessionCreationTime(event)
			if creationTime != "" {
				parentSessionMapKey = fmt.Sprintf("%s:%s:%s", email, roleID, creationTime)
			} else {
				normalizedUA := session.NormalizeUserAgent(event.UserAgent)
				cliKey, _ := session.GenerateSessionKey(email, roleID, normalizedUA, event.EventTime)
				if cliKey != "" {
					parentSessionMapKey = cliKey
				}
			}
		}
		if parentSessionMapKey == "" {
			continue
		}

		// Parse event time and compute TTL
		eventT, err := time.Parse(time.RFC3339, event.EventTime)
		if err != nil {
			log.Printf("WARNING: chain link: could not parse event time %s: %v", event.EventTime, err)
			continue
		}
		ttl := eventT.Add(chainLinkTTLHours * time.Hour).Unix()

		link := &types.DynamoDBChainLink{
			AccessKeyID:         issuedKeyID,
			ParentSessionMapKey: parentSessionMapKey,
			ParentEmail:         email,
			ParentRoleARN:       roleARN,
			AssumedRoleARN:      assumedRoleARN,
			TTL:                 ttl,
		}
		newChainLinks[issuedKeyID] = link

		if cfg.Tables.ChainLinks != "" {
			if err := ddblib.WriteChainLinkToDynamoDB(ctx, ddbClient, cfg.Tables.ChainLinks, link); err != nil {
				log.Printf("WARNING: failed to write chain link: %v", err)
			}
		}

		// For console switch-role, the assumed role's events use a fresh credential per
		// request rather than a single stable session key. Write a second chain link keyed
		// by "childRoleID:eventTime" so Pass 2 can match those events by role+creationTime.
		childRoleID := ExtractAssumedRoleID(event)
		if childRoleID != "" {
			consoleKey := childRoleID + ":" + event.EventTime
			consoleLink := &types.DynamoDBChainLink{
				AccessKeyID:         consoleKey,
				ParentSessionMapKey: parentSessionMapKey,
				ParentEmail:         email,
				ParentRoleARN:       roleARN,
				AssumedRoleARN:      assumedRoleARN,
				TTL:                 ttl,
			}
			newChainLinks[consoleKey] = consoleLink
			if cfg.Tables.ChainLinks != "" {
				if err := ddblib.WriteChainLinkToDynamoDB(ctx, ddbClient, cfg.Tables.ChainLinks, consoleLink); err != nil {
					log.Printf("WARNING: failed to write console chain link: %v", err)
				}
			}
		}
	}

	// === Pre-pass 2: Batch-load chain links from DynamoDB ===
	// Collect lookup keys for events that may be chained:
	//   - Access key ID (programmatic AssumeRole)
	//   - "roleID:creationTime" composite key (console switch-role)
	var unkeyedAccessKeyIDs []string
	seen := make(map[string]bool)
	for _, event := range events {
		// Access key lookup (programmatic)
		keyID := event.UserIdentity.AccessKeyID
		if keyID != "" && !seen[keyID] {
			if _, inBatch := newChainLinks[keyID]; !inBatch {
				seen[keyID] = true
				unkeyedAccessKeyIDs = append(unkeyedAccessKeyIDs, keyID)
			}
		}
		// Console key lookup: roleID:creationTime
		rID := session.ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)
		ct := session.GetSessionCreationTime(event)
		if rID != "" && ct != "" {
			consoleKey := rID + ":" + ct
			if !seen[consoleKey] {
				if _, inBatch := newChainLinks[consoleKey]; !inBatch {
					seen[consoleKey] = true
					unkeyedAccessKeyIDs = append(unkeyedAccessKeyIDs, consoleKey)
				}
			}
		}
	}

	// Batch-fetch from DynamoDB (only if we have something to look up)
	var ddbChainLinks map[string]*types.DynamoDBChainLink
	if len(unkeyedAccessKeyIDs) > 0 && cfg.Tables.ChainLinks != "" {
		var fetchErr error
		ddbChainLinks, fetchErr = ddblib.BatchGetChainLinks(ctx, ddbClient, cfg.Tables.ChainLinks, unkeyedAccessKeyIDs)
		if fetchErr != nil {
			log.Printf("WARNING: batch get chain links failed: %v", fetchErr)
			ddbChainLinks = make(map[string]*types.DynamoDBChainLink)
		}
	} else {
		ddbChainLinks = make(map[string]*types.DynamoDBChainLink)
	}

	// resolveChainLink returns the chain link for a given access key ID, checking
	// both the batch-local map and the DynamoDB-fetched map.
	resolveChainLink := func(keyID string) *types.DynamoDBChainLink {
		if link, ok := newChainLinks[keyID]; ok {
			return link
		}
		if link, ok := ddbChainLinks[keyID]; ok {
			return link
		}
		return nil
	}

	// === Pass 2: Aggregate all events ===
	for _, event := range events {
		eventTime := event.EventTime
		eventDate := eventTime[:10] // YYYY-MM-DD

		// Skip synthetic sessions that aren't real human activity
		if strings.Contains(event.UserIdentity.PrincipalID, "ConfigResourceCompositionSession") {
			continue
		}

		// Skip SwitchRole signin events — these are console bookkeeping generated when a
		// user switches roles in the browser. They don't represent real API activity and
		// lack sessionContext.creationDate, which would cause them to create a spurious
		// unlinked session record instead of being attributed to the chained session.
		if event.EventName == "SwitchRole" && event.EventSource == "signin.amazonaws.com" {
			continue
		}

		// Extract core identifiers
		email := session.ExtractEmailFromPrincipalID(event.UserIdentity.PrincipalID)
		roleARN := session.GetRoleARN(event)
		if roleARN == "" {
			roleARN = event.UserIdentity.ARN
		}

		roleID := session.ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)

		// Role chain attribution: check whether this event belongs to a chained (assumed) session.
		// Two lookup strategies:
		//   1. Programmatic: match by access key ID (stable per AssumeRole call)
		//   2. Console switch-role: match by "childRoleID:creationTime" since the console
		//      issues a new short-lived credential per request, not a single session key.
		var chainedFromLink *types.DynamoDBChainLink
		if event.UserIdentity.AccessKeyID != "" {
			chainedFromLink = resolveChainLink(event.UserIdentity.AccessKeyID)
		}
		if chainedFromLink == nil && roleID != "" {
			// Try console key: roleID:creationTime
			creationTime := session.GetSessionCreationTime(event)
			if creationTime != "" {
				consoleKey := roleID + ":" + creationTime
				chainedFromLink = resolveChainLink(consoleKey)
			}
		}
		if chainedFromLink != nil {
			log.Printf("CHAIN_ATTR: access_key=%s role=%s -> parent_session=%s assumed_role=%s event=%s:%s",
				event.UserIdentity.AccessKeyID, roleID, chainedFromLink.ParentSessionMapKey,
				chainedFromLink.AssumedRoleARN, event.EventSource, event.EventName)
		}

		// Account ID fallback chain
		accountID := session.ExtractAccountIDFromARN(roleARN)
		if accountID == "" {
			accountID = event.UserIdentity.AccountID
		}
		if accountID == "" && event.UserIdentity.ARN != "" {
			accountID = session.ExtractAccountIDFromARN(event.UserIdentity.ARN)
		}

		// Build session keys
		var sessionMapKey, truncatedSessionID, sessionCreationTime string
		if email != "" && roleID != "" {
			normalizedUserAgent := session.NormalizeUserAgent(event.UserAgent)
			cliSessionKey, cliStartTime := session.GenerateSessionKey(email, roleID, normalizedUserAgent, eventTime)

			if cliSessionKey != "" {
				sessionMapKey = cliSessionKey
				sessionCreationTime = cliStartTime
				truncatedSessionID = fmt.Sprintf("%s:%s", email, roleID)
			} else {
				sessionCreationTime = session.GetSessionCreationTime(event)
				if sessionCreationTime != "" {
					truncatedSessionID = fmt.Sprintf("%s:%s", email, roleID)
					sessionMapKey = fmt.Sprintf("%s:%s:%s", email, roleID, sessionCreationTime)
				}
			}
		}

		eventSource := event.EventSource

		// Role chain attribution: route chained events into a dedicated child session record.
		// The child session is keyed by the issued access key ID.
		// The parent session gets updated with summary counts and a reference to the child session key.
		if chainedFromLink != nil {
			// Child session key: always use a natural key.
			// Console switch-role: sessionMapKey is already set (email:roleID:creationTime).
			// Programmatic AssumeRole: no email in events, but we have roleID and eventTime.
			var childSessionMapKey, childSessionID string
			if sessionMapKey != "" {
				// Console switch-role: use the natural session key.
				childSessionMapKey = sessionMapKey
				childSessionID = truncatedSessionID
			} else {
				// Programmatic AssumeRole: key by the issued access key ID — stable across all
				// events in the session (unlike event time which changes per event).
				childSessionMapKey = chainedFromLink.AccessKeyID
				childSessionID = childSessionMapKey
			}

			// Child session's role identity comes from the chain link
			childRoleARN := chainedFromLink.AssumedRoleARN
			childRoleName := session.ExtractRoleNameFromARN(childRoleARN)
			childAccountID := session.ExtractAccountIDFromARN(childRoleARN)
			if childAccountID == "" {
				childAccountID = accountID // fall back to event's account
			}
			childEmail := chainedFromLink.ParentEmail
			parentSessionKey := chainedFromLink.ParentSessionMapKey

			normalizedUA := session.NormalizeUserAgent(event.UserAgent)
			resourceList := resources.ExtractResources(event)

			// For console switch-role, use the real session creation time and type.
			// For programmatic AssumeRole, use the event time as the start.
			childStartTime := eventTime
			childSessionType := "cli-sdk"
			if sessionCreationTime != "" {
				childStartTime = sessionCreationTime
				childSessionType = session.ClassifySessionType(normalizedUA)
				if childSessionType == "" {
					childSessionType = "web-console"
				}
			}

			// Process the event into the child session
			processChainedSessionEvent(sessions, ns, childSessionMapKey, childSessionID,
				childEmail, childRoleARN, childRoleName, childAccountID,
				parentSessionKey, childStartTime, eventTime, event.SourceIPAddress, normalizedUA,
				childSessionType, eventSource, event.EventName, event.ErrorCode, event.ErrorMessage, resourceList, eventDate)
			addToSet(sessionServices, childSessionMapKey, eventSource)
			addToSet(sessionResources, childSessionMapKey, childRoleARN)

			// Update parent session: bump chained counters and register child session key.
			// If the parent is in-memory (same batch), update directly.
			// Otherwise, defer a DynamoDB UpdateItem so it gets applied after all sessions are written.
			if parentSess, exists := sessions[parentSessionKey]; exists {
				parentSess.ChainedEventCount++
				// Track assumed role ARN
				foundRole := false
				for _, r := range parentSess.ChainedRoles {
					if r == childRoleARN {
						foundRole = true
						break
					}
				}
				if !foundRole {
					parentSess.ChainedRoles = append(parentSess.ChainedRoles, childRoleARN)
				}
				// Track child session key (for UI linking)
				foundKey := false
				for _, k := range parentSess.ChainedSessionKeys {
					if k == childSessionMapKey {
						foundKey = true
						break
					}
				}
				if !foundKey {
					parentSess.ChainedSessionKeys = append(parentSess.ChainedSessionKeys, childSessionMapKey)
				}
			} else {
				// Parent was ingested in a prior batch — schedule a DDB update after writes.
				deferredParentUpdates = append(deferredParentUpdates, parentUpdate{
					parentSessionMapKey: parentSessionKey,
					childSessionMapKey:  childSessionMapKey,
					childRoleARN:        childRoleARN,
				})
			}

			// Skip rest of normal processing for this event — it belongs to the child session
			continue
		}

		if event.ErrorCode != "" {
			log.Printf("EVENT_ERROR: event=%s:%s errorCode=%s email=%s", eventSource, event.EventName, event.ErrorCode, email)
		}

		// Process person
		if email != "" {
			processPersonEvent(people, email, accountID, roleARN, eventSource, eventDate)
			addToSet(personAccounts, email, accountID)
			addToSet(personRoles, email, roleARN)
			addToSet(personServices, email, eventSource)
			addToSet(personSessions, email, sessionMapKey)
		}

		// Process session
		if sessionMapKey != "" && accountID != "" && roleARN != "" {
			normalizedUserAgent := session.NormalizeUserAgent(event.UserAgent)
			resourceList := resources.ExtractResources(event)
			processSessionEvent(sessions, people, ns, sessionMapKey, truncatedSessionID, email, roleID, accountID, roleARN, session.ExtractRoleNameFromARN(roleARN),
				sessionCreationTime, eventTime, event.SourceIPAddress, normalizedUserAgent, eventSource, event.EventName, event.ErrorCode, event.ErrorMessage, resourceList, eventDate)
			addToSet(sessionServices, sessionMapKey, eventSource)
		} else if sessionMapKey != "" {
			log.Printf("SKIPPED_SESSION: email=%s roleID=%s accountID=%s roleARN=%s eventSource=%s eventName=%s",
				email, roleID, accountID, roleARN, eventSource, event.EventName)
		}

		// Process account
		if accountID != "" {
			processAccountEvent(accounts, accountID, email, sessionMapKey, roleARN, eventSource, eventDate)
			addToSet(accountPeople, accountID, email)
			addToSet(accountSessions, accountID, sessionMapKey)
			addToSet(accountRoles, accountID, roleARN)
			addToSet(accountServices, accountID, eventSource)
		}

		// Process role
		if roleARN != "" {
			if err := processRoleEvent(roles, event, roleARN, eventDate); err != nil {
				log.Printf("WARNING: Failed to process role event: %v", err)
			}
			addToSet(rolePeople, roleARN, email)
			addToSet(roleSessions, roleARN, sessionMapKey)
			addToSet(roleAccounts, roleARN, accountID)
		}

		// Process service
		if err := processServiceEvent(services, event, roleARN, eventDate); err != nil {
			log.Printf("WARNING: Failed to process service event: %v", err)
		}
		addToSet(servicePeople, eventSource, email)
		addToSet(serviceSessions, eventSource, sessionMapKey)
		addToSet(serviceAccounts, eventSource, accountID)

		// Process resources
		resourceList := resources.ExtractResources(event)
		for _, resource := range resourceList {
			if err := processResourceEvent(resourceMap, event, resource, accountID, eventDate); err != nil {
				log.Printf("WARNING: Failed to process resource event: %v", err)
			}

			// Track ClickOps operations
			if sessionMapKey != "" {
				if sess, exists := sessions[sessionMapKey]; exists {
					if sess.SessionType == "web-console" && session.IsClickOpsOperation(event.EventName) {
						if resourceEntry, exists := resourceMap[resource]; exists {
							found := false
							for i := range resourceEntry.ClickOpsAccesses {
								access := &resourceEntry.ClickOpsAccesses[i]
								if access.SessionID == truncatedSessionID && access.EventName == event.EventName {
									access.EventCount++
									found = true
									break
								}
							}
							if !found {
								log.Printf("DEBUG: Adding ClickOps access for resource=%s event=%s sessionCreationTime='%s' eventDate='%s'", resource, event.EventName, sessionCreationTime, eventDate)
								resourceEntry.ClickOpsAccesses = append(resourceEntry.ClickOpsAccesses, types.ClickOpsAccess{
									SessionID:   truncatedSessionID,
									PersonEmail: email,
									EventName:   event.EventName,
									AccessTime:  sessionCreationTime,
									EventCount:  1,
									AccountID:   accountID,
								})
							}
							resourceEntry.ClickOpsCount++
						}
					}
				}
			}

			addToSet(resourcePeople, resource, email)
			addToSet(resourceSessions, resource, sessionMapKey)
			if email != "" {
				addToSet(personResources, email, resource)
			}
			if sessionMapKey != "" {
				addToSet(sessionResources, sessionMapKey, resource)
			}
			if accountID != "" {
				addToSet(accountResources, accountID, resource)
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
	for email, person := range people {
		person.AccountsCount = setLen(personAccounts, email)
		person.RolesCount = setLen(personRoles, email)
		person.ServicesCount = setLen(personServices, email)
		person.ResourcesCount = setLen(personResources, email)
		person.SessionsCount = setLen(personSessions, email)
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

	// Rewrite ChainedSessionKeys from map keys to full session_start values so the
	// CLI can do direct lookups without guessing the start time.
	for _, sess := range sessions {
		if len(sess.ChainedSessionKeys) == 0 {
			continue
		}
		resolved := make([]string, 0, len(sess.ChainedSessionKeys))
		for _, mapKey := range sess.ChainedSessionKeys {
			if child, ok := sessions[mapKey]; ok && child.SessionStart != "" {
				resolved = append(resolved, child.SessionStart)
			} else {
				resolved = append(resolved, mapKey) // keep as-is if child not in this batch
			}
		}
		sess.ChainedSessionKeys = resolved
	}

	// Write aggregated data to DynamoDB (skip when client is nil, e.g. in tests)
	if ddbClient == nil {
		return sessions, nil
	}

	for _, role := range roles {
		role.CustomerID = ns
		eventNames := make([]string, 0, len(role.TopEventNames))
		for k := range role.TopEventNames {
			eventNames = append(eventNames, k)
		}
		deniedEventNames := make([]string, 0, len(role.TopDeniedEventNames))
		for k := range role.TopDeniedEventNames {
			deniedEventNames = append(deniedEventNames, k)
		}
		log.Printf("ROLE_WRITE_ATTEMPT: customerId=%s arn=%s events=%d top_event_names=%d services_count=%d resources_count=%d event_names=%v",
			role.CustomerID, role.ARN, role.TotalEvents, len(role.TopEventNames), len(role.ServicesCount), len(role.ResourcesCount), eventNames)
		log.Printf("ROLE_WRITE_DENIED: arn=%s total_denied_events=%d denied_event_names=%v denied_resources_count=%d",
			role.ARN, role.TotalDeniedEvents, deniedEventNames, len(role.DeniedResourceAccesses))
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

	// Log summary
	log.Printf("=== Aggregation Summary ===")
	log.Printf("Found %d unique people, %d sessions, %d roles, %d services, %d resources, %d accounts",
		len(people), len(sessions), len(roles), len(services), len(resourceMap), len(accounts))

	cliSessions := 0
	webSessions := 0
	for _, sess := range sessions {
		if sess.SessionType == "cli-sdk" {
			cliSessions++
		} else if sess.SessionType == "web-console" {
			webSessions++
		}
	}
	log.Printf("Session breakdown: %d CLI/SDK sessions, %d web console sessions", cliSessions, webSessions)

	for _, sess := range sessions {
		log.Printf("Session: type=%s email=%s role=%s account=%s events=%d startTime=%s",
			sess.SessionType, sess.PersonEmail, sess.RoleName, sess.AccountID, sess.EventsCount, sess.StartTime)
	}
	for _, role := range roles {
		log.Printf("Role: arn=%s account=%s events=%d", role.ARN, role.AccountID, role.TotalEvents)
	}
	for _, account := range accounts {
		log.Printf("Account: id=%s events=%d people=%d sessions=%d", account.AccountID, account.EventsCount, account.PeopleCount, account.SessionsCount)
	}

	for _, person := range people {
		person.CustomerID = ns
		if err := ddblib.WritePersonToDynamoDB(ctx, ddbClient, cfg.Tables.People, person); err != nil {
			log.Printf("ERROR: Failed to write person: %v", err)
		}
	}

	for _, sess := range sessions {
		if sess.StartTime != "" && sess.EndTime != "" {
			startTime, _ := time.Parse(time.RFC3339, sess.StartTime)
			endTime, _ := time.Parse(time.RFC3339, sess.EndTime)
			sess.DurationMinutes = int(endTime.Sub(startTime).Minutes())
		}
		sess.CustomerID = ns
		if err := ddblib.WriteSessionToDynamoDB(ctx, ddbClient, cfg.Tables.Sessions, sess); err != nil {
			log.Printf("ERROR: Failed to write session: %v", err)
		}
	}

	// Flush deferred parent chaining updates (parent sessions ingested in prior batches).
	if len(deferredParentUpdates) > 0 && cfg.Tables.Sessions != "" {
		// Deduplicate: only send one update per (parent, child) pair.
		seen := make(map[string]bool)
		for _, u := range deferredParentUpdates {
			key := u.parentSessionMapKey + "|" + u.childSessionMapKey
			if seen[key] {
				continue
			}
			seen[key] = true
			if err := ddblib.UpdateParentSessionChaining(ctx, ddbClient, cfg.Tables.Sessions, ns,
				u.parentSessionMapKey, u.childSessionMapKey, u.childRoleARN); err != nil {
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

// processPersonEvent tracks aggregated data for a person.
func processPersonEvent(people map[string]*types.DynamoDBPerson, email, accountID, roleARN, eventSource, eventDate string) {
	person, exists := people[email]
	if !exists {
		person = &types.DynamoDBPerson{
			Email:     email,
			FirstSeen: eventDate,
			LastSeen:  eventDate,
		}
		people[email] = person
	}
	person.LastSeen = eventDate
	person.EventsCount++
}

// processSessionEvent tracks aggregated data for a session.
func processSessionEvent(sessions map[string]*types.DynamoDBSessionAggregated, people map[string]*types.DynamoDBPerson, ns, sessionMapKey, truncatedSessionID, email, roleID, accountID, roleARN, roleName, sessionCreationTime, eventTime, sourceIP, userAgent, eventSource, eventName, errorCode, errorMessage string, resourceList []string, eventDate string) {
	sess, exists := sessions[sessionMapKey]
	if !exists {
		displayName := ""
		if person, personExists := people[email]; personExists {
			displayName = person.DisplayName
		}

		sessionType := session.ClassifySessionType(userAgent)
		if sessionType == "" {
			log.Printf("SKIPPED: Unrecognized session type - email:%s role:%s userAgent:%s", email, roleID, userAgent)
			return
		}

		sess = &types.DynamoDBSessionAggregated{
			CustomerID:              ns,
			SessionID:               truncatedSessionID,
			SessionType:             sessionType,
			SessionStart:            sessionCreationTime + "#" + truncatedSessionID,
			StartTime:               sessionCreationTime,
			PersonEmail:             email,
			PersonDisplayName:       displayName,
			AccountID:               accountID,
			RoleARN:                 roleARN,
			RoleName:                roleName,
			SourceIPs:               []string{},
			UserAgents:              []string{},
			EventCounts:             make(map[string]int),
			ResourcesAccessed:       make(map[string]int),
			ResourceAccesses:        []types.ResourceAccess{},
			DeniedEventCount:        0,
			DeniedEventCounts:       make(map[string]int),
			DeniedResourcesAccessed: make(map[string]int),
			DeniedResourceAccesses:  []types.ResourceAccess{},
			DeniedEventAccesses:     []types.EventAccess{},
		}
		sessions[sessionMapKey] = sess
	}

	sess.EndTime = eventTime

	isAccessDenied := session.IsAccessDeniedError(errorCode)
	eventKey := fmt.Sprintf("%s:%s", eventSource, eventName)

	if isAccessDenied {
		policyInfo := session.ExtractPolicyInfo(errorMessage)
		if policyInfo.PolicyARN != "" {
			log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s policy_arn=%s policy_type=%s errorMessage=%q", sessionMapKey, eventKey, errorCode, policyInfo.PolicyARN, policyInfo.PolicyType, errorMessage)
		} else {
			log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s errorMessage=%q", sessionMapKey, eventKey, errorCode, errorMessage)
		}
		sess.DeniedEventCount++
		sess.DeniedEventCounts[eventKey]++

		if len(resourceList) > 0 {
			for _, resource := range resourceList {
				sess.DeniedResourcesAccessed[resource]++
				found := false
				for i := range sess.DeniedResourceAccesses {
					if sess.DeniedResourceAccesses[i].Resource == resource &&
						sess.DeniedResourceAccesses[i].Service == eventSource &&
						sess.DeniedResourceAccesses[i].EventName == eventName &&
						sess.DeniedResourceAccesses[i].PolicyARN == policyInfo.PolicyARN {
						sess.DeniedResourceAccesses[i].Count++
						found = true
						break
					}
				}
				if !found {
					sess.DeniedResourceAccesses = append(sess.DeniedResourceAccesses, types.ResourceAccess{
						Resource:     resource,
						Service:      eventSource,
						EventName:    eventName,
						Count:        1,
						PolicyARN:    policyInfo.PolicyARN,
						PolicyType:   policyInfo.PolicyType,
						ErrorMessage: errorMessage,
					})
				}
			}
		} else {
			found := false
			for i := range sess.DeniedEventAccesses {
				if sess.DeniedEventAccesses[i].Service == eventSource &&
					sess.DeniedEventAccesses[i].EventName == eventName &&
					sess.DeniedEventAccesses[i].PolicyARN == policyInfo.PolicyARN {
					sess.DeniedEventAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.DeniedEventAccesses = append(sess.DeniedEventAccesses, types.EventAccess{
					Service:      eventSource,
					EventName:    eventName,
					Count:        1,
					PolicyARN:    policyInfo.PolicyARN,
					PolicyType:   policyInfo.PolicyType,
					ErrorMessage: errorMessage,
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
					sess.ResourceAccesses[i].Service == eventSource &&
					sess.ResourceAccesses[i].EventName == eventName {
					sess.ResourceAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.ResourceAccesses = append(sess.ResourceAccesses, types.ResourceAccess{
					Resource:  resource,
					Service:   eventSource,
					EventName: eventName,
					Count:     1,
				})
			}
		}
	}

	// Track ClickOps operations
	if !isAccessDenied && sess.SessionType == "web-console" && session.IsClickOpsOperation(eventName) {
		sess.ClickOpsEventCount++
		if sess.ClickOpsEventCounts == nil {
			sess.ClickOpsEventCounts = make(map[string]int)
		}
		sess.ClickOpsEventCounts[eventName]++
	}

	// Add source IP if valid and not duplicate
	if sourceIP != "" && session.IsValidSourceIP(sourceIP) {
		found := false
		for _, ip := range sess.SourceIPs {
			if ip == sourceIP {
				found = true
				break
			}
		}
		if !found {
			sess.SourceIPs = append(sess.SourceIPs, sourceIP)
		}
	}

	// Add user agent if valid and not duplicate
	if userAgent != "" && session.IsValidUserAgent(userAgent) {
		found := false
		for _, ua := range sess.UserAgents {
			if ua == userAgent {
				found = true
				break
			}
		}
		if !found {
			sess.UserAgents = append(sess.UserAgents, userAgent)
		}
	}
}

// processChainedSessionEvent accumulates events into a child (chained role) session record.
// The child session is keyed by childSessionMapKey (stable per access key ID) and stores
// a back-reference to the parent human session via ParentSessionKey.
func processChainedSessionEvent(
	sessions map[string]*types.DynamoDBSessionAggregated,
	ns, childSessionMapKey, childSessionID,
	parentEmail, roleARN, roleName, accountID,
	parentSessionKey, startTime, eventTime, sourceIP, userAgent,
	sessionType, eventSource, eventName, errorCode, errorMessage string,
	resourceList []string,
	eventDate string,
) {
	sess, exists := sessions[childSessionMapKey]
	if !exists {
		sess = &types.DynamoDBSessionAggregated{
			CustomerID:              ns,
			SessionID:               childSessionID,
			SessionType:             sessionType,
			SessionStart:            startTime + "#" + childSessionID,
			StartTime:               startTime,
			PersonEmail:             parentEmail, // shows whose session originated this
			AccountID:               accountID,
			RoleARN:                 roleARN,
			RoleName:                roleName,
			ParentSessionKey:        parentSessionKey,
			ParentEmail:             parentEmail,
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
		sessions[childSessionMapKey] = sess
	}

	sess.EndTime = eventTime
	isAccessDenied := session.IsAccessDeniedError(errorCode)
	eventKey := fmt.Sprintf("%s:%s", eventSource, eventName)

	if isAccessDenied {
		policyInfo := session.ExtractPolicyInfo(errorMessage)
		sess.DeniedEventCount++
		sess.DeniedEventCounts[eventKey]++
		if len(resourceList) > 0 {
			for _, resource := range resourceList {
				sess.DeniedResourcesAccessed[resource]++
				found := false
				for i := range sess.DeniedResourceAccesses {
					if sess.DeniedResourceAccesses[i].Resource == resource &&
						sess.DeniedResourceAccesses[i].Service == eventSource &&
						sess.DeniedResourceAccesses[i].EventName == eventName {
						sess.DeniedResourceAccesses[i].Count++
						found = true
						break
					}
				}
				if !found {
					sess.DeniedResourceAccesses = append(sess.DeniedResourceAccesses, types.ResourceAccess{
						Resource:     resource,
						Service:      eventSource,
						EventName:    eventName,
						Count:        1,
						PolicyARN:    policyInfo.PolicyARN,
						PolicyType:   policyInfo.PolicyType,
						ErrorMessage: errorMessage,
					})
				}
			}
		} else {
			found := false
			for i := range sess.DeniedEventAccesses {
				if sess.DeniedEventAccesses[i].Service == eventSource &&
					sess.DeniedEventAccesses[i].EventName == eventName &&
					sess.DeniedEventAccesses[i].PolicyARN == policyInfo.PolicyARN {
					sess.DeniedEventAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.DeniedEventAccesses = append(sess.DeniedEventAccesses, types.EventAccess{
					Service:      eventSource,
					EventName:    eventName,
					Count:        1,
					PolicyARN:    policyInfo.PolicyARN,
					PolicyType:   policyInfo.PolicyType,
					ErrorMessage: errorMessage,
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
					sess.ResourceAccesses[i].Service == eventSource &&
					sess.ResourceAccesses[i].EventName == eventName {
					sess.ResourceAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.ResourceAccesses = append(sess.ResourceAccesses, types.ResourceAccess{
					Resource:  resource,
					Service:   eventSource,
					EventName: eventName,
					Count:     1,
				})
			}
		}
	}

	if sourceIP != "" && session.IsValidSourceIP(sourceIP) {
		found := false
		for _, ip := range sess.SourceIPs {
			if ip == sourceIP {
				found = true
				break
			}
		}
		if !found {
			sess.SourceIPs = append(sess.SourceIPs, sourceIP)
		}
	}

	if userAgent != "" && session.IsValidUserAgent(userAgent) {
		found := false
		for _, ua := range sess.UserAgents {
			if ua == userAgent {
				found = true
				break
			}
		}
		if !found {
			sess.UserAgents = append(sess.UserAgents, userAgent)
		}
	}
}

// processAccountEvent tracks aggregated data for an account.
func processAccountEvent(accounts map[string]*types.DynamoDBAccount, accountID, email, sessionID, roleARN, eventSource, eventDate string) {
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
		found := false
		for _, existingRole := range svc.RolesUsing {
			if existingRole == roleARN {
				found = true
				break
			}
		}
		if !found {
			svc.RolesUsing = append(svc.RolesUsing, roleARN)
		}
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
		found := false
		for _, existingRole := range resource.RolesUsing {
			if existingRole == roleARN {
				found = true
				break
			}
		}
		if !found {
			resource.RolesUsing = append(resource.RolesUsing, roleARN)
		}
	}

	if resource.ServicesUsed == nil {
		resource.ServicesUsed = []string{}
	}
	found := false
	for _, existingService := range resource.ServicesUsed {
		if existingService == event.EventSource {
			found = true
			break
		}
	}
	if !found {
		resource.ServicesUsed = append(resource.ServicesUsed, event.EventSource)
	}

	return nil
}
