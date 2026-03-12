package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/parser"
	"github.com/engseclabs/trailtool/ingestor/lib/resources"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// Hardcoded single-tenant customer ID
const defaultCustomerID = "default"

// Table names from environment variables
var (
	rolesAggregatedTable     = getEnvOrDefault("ROLES_AGGREGATED_TABLE", "trailtool-roles-aggregated")
	servicesAggregatedTable  = getEnvOrDefault("SERVICES_AGGREGATED_TABLE", "trailtool-services-aggregated")
	resourcesAggregatedTable = getEnvOrDefault("RESOURCES_AGGREGATED_TABLE", "trailtool-resources-aggregated")
	peopleAggregatedTable    = getEnvOrDefault("PEOPLE_AGGREGATED_TABLE", "trailtool-people-aggregated")
	sessionsAggregatedTable  = getEnvOrDefault("SESSIONS_AGGREGATED_TABLE", "trailtool-sessions-aggregated")
	accountsAggregatedTable  = getEnvOrDefault("ACCOUNTS_AGGREGATED_TABLE", "trailtool-accounts-aggregated")
)

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// processPersonEvent tracks aggregated data for a person
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

// processSessionEvent tracks aggregated data for a session
// sessionMapKey is the in-memory unique key (email:roleID:startTime) used for grouping events.
// truncatedSessionID is the stable partition key stored in DynamoDB (email:roleID) without creation time.
func processSessionEvent(sessions map[string]*types.DynamoDBSessionAggregated, people map[string]*types.DynamoDBPerson, customerID, sessionMapKey, truncatedSessionID, email, roleID, accountID, roleARN, roleName, sessionCreationTime, eventTime, sourceIP, userAgent, eventSource, eventName, errorCode, errorMessage string, resourceList []string, eventDate string) {
	sess, exists := sessions[sessionMapKey]
	if !exists {
		// Look up person display name
		displayName := ""
		if person, personExists := people[email]; personExists {
			displayName = person.DisplayName
		}

		// Classify session type based on first user agent seen
		sessionType := session.ClassifySessionType(userAgent)

		// Skip sessions with unrecognized user agents - don't create or merge them
		if sessionType == "" {
			log.Printf("SKIPPED: Unrecognized session type - email:%s role:%s userAgent:%s", email, roleID, userAgent)
			return
		}

		sess = &types.DynamoDBSessionAggregated{
			CustomerID:              customerID,
			SessionID:               truncatedSessionID,  // Partition key (stable person+role)
			SessionType:             sessionType,         // "web-console" or "cli-sdk"
			SessionStart:            sessionCreationTime, // Range key - IAM session creation time
			StartTime:               sessionCreationTime, // Kept for compatibility
			PersonEmail:             email,
			PersonDisplayName:       displayName,
			AccountID:               accountID,
			RoleARN:                 roleARN,
			RoleName:                roleName,
			SourceIPs:               []string{},
			UserAgents:              []string{},
			EventCounts:             make(map[string]int),
			ResourcesAccessed:       make(map[string]int),
			ResourceAccesses:        []types.ResourceAccess{}, // Will be populated during event processing
			DeniedEventCount:        0,
			DeniedEventCounts:       make(map[string]int),
			DeniedResourcesAccessed: make(map[string]int),
			DeniedResourceAccesses:  []types.ResourceAccess{},
			DeniedEventAccesses:     []types.EventAccess{},
		}
		sessions[sessionMapKey] = sess
	}

	sess.EndTime = eventTime

	// Check if this is an AccessDenied error
	isAccessDenied := session.IsAccessDeniedError(errorCode)

	// Track event counts (flattened eventSource:eventName)
	eventKey := fmt.Sprintf("%s:%s", eventSource, eventName)

	if isAccessDenied {
		// Extract policy info from error message (AWS Jan 2026 update includes policy ARNs)
		policyInfo := session.ExtractPolicyInfo(errorMessage)
		if policyInfo.PolicyARN != "" {
			log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s policy_arn=%s policy_type=%s errorMessage=%q", sessionMapKey, eventKey, errorCode, policyInfo.PolicyARN, policyInfo.PolicyType, errorMessage)
		} else {
			log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s errorMessage=%q", sessionMapKey, eventKey, errorCode, errorMessage)
		}
		// Track denied events separately
		sess.DeniedEventCount++
		sess.DeniedEventCounts[eventKey]++

		if len(resourceList) > 0 {
			// Track denied resources accessed (both old format and new detailed format)
			for _, resource := range resourceList {
				sess.DeniedResourcesAccessed[resource]++

				// Track detailed denied resource access (service + event + resource + count + policy info)
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
			// Track denied events without specific resources
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
		// Track successful events (existing logic)
		sess.EventsCount++
		sess.EventCounts[eventKey]++

		// Track resources accessed (both old format and new detailed format)
		for _, resource := range resourceList {
			sess.ResourcesAccessed[resource]++

			// Track detailed resource access (service + event + resource + count)
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

	// Track ClickOps operations (web console create/modify operations)
	if !isAccessDenied && sess.SessionType == "web-console" && session.IsClickOpsOperation(eventName) {
		sess.ClickOpsEventCount++
		if sess.ClickOpsEventCounts == nil {
			sess.ClickOpsEventCounts = make(map[string]int)
		}
		sess.ClickOpsEventCounts[eventName]++
	}

	// Add source IP if not already present and it's a valid user IP
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

	// Add user agent if not already present and it's a valid user agent (not service-to-service)
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

	// Duration will be computed at end
}

// processAccountEvent tracks aggregated data for an account
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

	// Unique counts will be calculated from tracking sets in main function
}

// ProcessRolesServicesResources processes all events for roles, services, and resources
// Now also processes people, sessions, and accounts (noun-based architecture)
func ProcessRolesServicesResources(ctx context.Context, ddbClient *dynamodb.Client, customerID string, ctEvents []types.CloudTrailRecord) error {
	log.Printf("=== Processing Noun-Based Aggregation ===")
	log.Printf("Processing %d events for aggregation (customer: %s)", len(ctEvents), customerID)

	// Aggregation maps for all nouns
	roles := make(map[string]*types.DynamoDBRole)
	services := make(map[string]*types.DynamoDBService)
	resourceMap := make(map[string]*types.DynamoDBResource)
	people := make(map[string]*types.DynamoDBPerson)
	sessions := make(map[string]*types.DynamoDBSessionAggregated)
	accounts := make(map[string]*types.DynamoDBAccount)

	// Tracking sets for unique counts
	rolepeople := make(map[string]map[string]bool)       // role -> set of people
	rolesessions := make(map[string]map[string]bool)     // role -> set of sessions
	roleAccounts := make(map[string]map[string]bool)     // role -> set of accounts
	servicePeople := make(map[string]map[string]bool)    // service -> set of people
	serviceSessions := make(map[string]map[string]bool)  // service -> set of sessions
	serviceAccounts := make(map[string]map[string]bool)  // service -> set of accounts
	resourcePeople := make(map[string]map[string]bool)   // resource -> set of people
	resourceSessions := make(map[string]map[string]bool) // resource -> set of sessions
	personAccounts := make(map[string]map[string]bool)   // person -> set of accounts
	personRoles := make(map[string]map[string]bool)      // person -> set of roles
	personServices := make(map[string]map[string]bool)   // person -> set of services
	personResources := make(map[string]map[string]bool)  // person -> set of resources
	personSessions := make(map[string]map[string]bool)   // person -> set of sessions
	accountPeople := make(map[string]map[string]bool)    // account -> set of people
	accountSessions := make(map[string]map[string]bool)  // account -> set of sessions
	accountRoles := make(map[string]map[string]bool)     // account -> set of roles
	accountServices := make(map[string]map[string]bool)  // account -> set of services
	accountResources := make(map[string]map[string]bool) // account -> set of resources
	sessionServices := make(map[string]map[string]bool)  // session -> set of services
	sessionResources := make(map[string]map[string]bool) // session -> set of resources

	// Aggregate all events
	for _, event := range ctEvents {
		eventTime := event.EventTime
		eventDate := eventTime[:10] // Extract date part YYYY-MM-DD

		// Skip synthetic sessions that aren't real human activity
		if strings.Contains(event.UserIdentity.PrincipalID, "ConfigResourceCompositionSession") {
			continue
		}

		// Extract core identifiers for this event
		email := session.ExtractEmailFromPrincipalID(event.UserIdentity.PrincipalID)
		roleARN := session.GetRoleARN(event)

		// Fallback to UserIdentity.ARN if SessionContext ARN is not available
		if roleARN == "" {
			roleARN = event.UserIdentity.ARN
		}

		roleID := session.ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)

		// Try to get account ID from multiple sources (fallback chain)
		accountID := session.ExtractAccountIDFromARN(roleARN)
		if accountID == "" {
			accountID = event.UserIdentity.AccountID
		}
		if accountID == "" && event.UserIdentity.ARN != "" {
			accountID = session.ExtractAccountIDFromARN(event.UserIdentity.ARN)
		}

		// Build unique in-memory key (includes creation time) and truncated stable ID for storage.
		// If there's an email, we track this as a session (person-initiated activity)
		var sessionMapKey, truncatedSessionID, sessionCreationTime string
		if email != "" && roleID != "" {
			// Normalize user agent by stripping brackets
			normalizedUserAgent := session.NormalizeUserAgent(event.UserAgent)

			// Try time-based windowing for CLI sessions first
			cliSessionKey, cliStartTime := session.GenerateSessionKey(email, roleID, normalizedUserAgent, eventTime)

			if cliSessionKey != "" {
				// CLI session: use 4-hour time window
				sessionMapKey = cliSessionKey
				sessionCreationTime = cliStartTime
				truncatedSessionID = fmt.Sprintf("%s:%s", email, roleID)
			} else {
				// Console session: use IAM creation time
				sessionCreationTime = session.GetSessionCreationTime(event)
				if sessionCreationTime != "" { // Only form key if we have creation time
					truncatedSessionID = fmt.Sprintf("%s:%s", email, roleID)
					sessionMapKey = fmt.Sprintf("%s:%s:%s", email, roleID, sessionCreationTime)
				}
			}
		}
		eventSource := event.EventSource

		// Log errorCode if present for debugging
		if event.ErrorCode != "" {
			log.Printf("EVENT_ERROR: event=%s:%s errorCode=%s email=%s", eventSource, event.EventName, event.ErrorCode, email)
		}

		// Process person (if email present)
		if email != "" {
			processPersonEvent(people, email, accountID, roleARN, eventSource, eventDate)

			// Track unique items for this person
			if accountID != "" {
				if personAccounts[email] == nil {
					personAccounts[email] = make(map[string]bool)
				}
				personAccounts[email][accountID] = true
			}
			if roleARN != "" {
				if personRoles[email] == nil {
					personRoles[email] = make(map[string]bool)
				}
				personRoles[email][roleARN] = true
			}
			if eventSource != "" {
				if personServices[email] == nil {
					personServices[email] = make(map[string]bool)
				}
				personServices[email][eventSource] = true
			}
			if sessionMapKey != "" {
				if personSessions[email] == nil {
					personSessions[email] = make(map[string]bool)
				}
				personSessions[email][sessionMapKey] = true
			}
		}

		// Process session (if sessionMapKey present - means we have email and session info)
		// Skip sessions with missing account or role info - these are incomplete
		if sessionMapKey != "" && accountID != "" && roleARN != "" {
			normalizedUserAgent := session.NormalizeUserAgent(event.UserAgent)
			resourceList := resources.ExtractResources(event)
			processSessionEvent(sessions, people, customerID, sessionMapKey, truncatedSessionID, email, roleID, accountID, roleARN, session.ExtractRoleNameFromARN(roleARN),
				sessionCreationTime, eventTime, event.SourceIPAddress, normalizedUserAgent, eventSource, event.EventName, event.ErrorCode, event.ErrorMessage, resourceList, eventDate)

			// Track unique services/resources for this session (keyed by sessionMapKey for uniqueness)
			if eventSource != "" {
				if sessionServices[sessionMapKey] == nil {
					sessionServices[sessionMapKey] = make(map[string]bool)
				}
				sessionServices[sessionMapKey][eventSource] = true
			}
		} else if sessionMapKey != "" {
			// Log when we skip a session due to missing critical data
			log.Printf("SKIPPED_SESSION: email=%s roleID=%s accountID=%s roleARN=%s eventSource=%s eventName=%s",
				email, roleID, accountID, roleARN, eventSource, event.EventName)
		}

		// Process account (if account ID present)
		if accountID != "" {
			processAccountEvent(accounts, accountID, email, sessionMapKey, roleARN, eventSource, eventDate)

			// Track unique items for this account
			if email != "" {
				if accountPeople[accountID] == nil {
					accountPeople[accountID] = make(map[string]bool)
				}
				accountPeople[accountID][email] = true
			}
			if sessionMapKey != "" {
				if accountSessions[accountID] == nil {
					accountSessions[accountID] = make(map[string]bool)
				}
				accountSessions[accountID][sessionMapKey] = true
			}
			if roleARN != "" {
				if accountRoles[accountID] == nil {
					accountRoles[accountID] = make(map[string]bool)
				}
				accountRoles[accountID][roleARN] = true
			}
			if eventSource != "" {
				if accountServices[accountID] == nil {
					accountServices[accountID] = make(map[string]bool)
				}
				accountServices[accountID][eventSource] = true
			}
		}

		// Process role if present
		if roleARN != "" {
			if err := processRoleEvent(roles, event, roleARN, eventDate); err != nil {
				log.Printf("WARNING: Failed to process role event: %v", err)
			}

			// Track unique people/sessions/accounts for this role
			if email != "" {
				if rolepeople[roleARN] == nil {
					rolepeople[roleARN] = make(map[string]bool)
				}
				rolepeople[roleARN][email] = true
			}
			if sessionMapKey != "" {
				if rolesessions[roleARN] == nil {
					rolesessions[roleARN] = make(map[string]bool)
				}
				rolesessions[roleARN][sessionMapKey] = true
			}
			if accountID != "" {
				if roleAccounts[roleARN] == nil {
					roleAccounts[roleARN] = make(map[string]bool)
				}
				roleAccounts[roleARN][accountID] = true
			}
		}

		// Process service
		if err := processServiceEvent(services, event, roleARN, eventDate); err != nil {
			log.Printf("WARNING: Failed to process service event: %v", err)
		}

		// Track unique people/sessions/accounts for this service
		if email != "" {
			if servicePeople[eventSource] == nil {
				servicePeople[eventSource] = make(map[string]bool)
			}
			servicePeople[eventSource][email] = true
		}
		if sessionMapKey != "" {
			if serviceSessions[eventSource] == nil {
				serviceSessions[eventSource] = make(map[string]bool)
			}
			serviceSessions[eventSource][sessionMapKey] = true
		}
		if accountID != "" {
			if serviceAccounts[eventSource] == nil {
				serviceAccounts[eventSource] = make(map[string]bool)
			}
			serviceAccounts[eventSource][accountID] = true
		}

		// Process resources
		resourceList := resources.ExtractResources(event)
		for _, resource := range resourceList {
			if err := processResourceEvent(resourceMap, event, resource, accountID, eventDate); err != nil {
				log.Printf("WARNING: Failed to process resource event: %v", err)
			}

			// Track ClickOps operations (web console create/modify operations)
			if sessionMapKey != "" {
				// Check if this is a web-console session and a ClickOps operation
				if sess, exists := sessions[sessionMapKey]; exists {
					if sess.SessionType == "web-console" && session.IsClickOpsOperation(event.EventName) {
						// Get or create the resource entry
						if resourceEntry, exists := resourceMap[resource]; exists {
							// Check if this ClickOps access already exists to update count
							found := false
							for i := range resourceEntry.ClickOpsAccesses {
								access := &resourceEntry.ClickOpsAccesses[i]
								if access.SessionID == truncatedSessionID && access.EventName == event.EventName {
									access.EventCount++
									found = true
									break
								}
							}

							// If not found, add new ClickOps access
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

							// Update total ClickOps count
							resourceEntry.ClickOpsCount++
						}
					}
				}
			}

			// Track unique people/sessions for this resource
			if email != "" {
				if resourcePeople[resource] == nil {
					resourcePeople[resource] = make(map[string]bool)
				}
				resourcePeople[resource][email] = true

				// Also track for person
				if personResources[email] == nil {
					personResources[email] = make(map[string]bool)
				}
				personResources[email][resource] = true
			}
			if sessionMapKey != "" {
				if resourceSessions[resource] == nil {
					resourceSessions[resource] = make(map[string]bool)
				}
				resourceSessions[resource][sessionMapKey] = true

				// Also track for session
				if sessionResources[sessionMapKey] == nil {
					sessionResources[sessionMapKey] = make(map[string]bool)
				}
				sessionResources[sessionMapKey][resource] = true
			}
			if accountID != "" {
				// Track for account
				if accountResources[accountID] == nil {
					accountResources[accountID] = make(map[string]bool)
				}
				accountResources[accountID][resource] = true
			}
		}
	} // Update counts in roles/services/resources based on unique sets
	for roleARN, role := range roles {
		if peopleSet, exists := rolepeople[roleARN]; exists {
			role.PeopleCount = len(peopleSet)
		}
		if sessionsSet, exists := rolesessions[roleARN]; exists {
			role.SessionsCount = len(sessionsSet)
		}
		if accountsSet, exists := roleAccounts[roleARN]; exists {
			role.AccountsCount = len(accountsSet)
		}
	}

	for eventSource, service := range services {
		if peopleSet, exists := servicePeople[eventSource]; exists {
			service.PeopleCount = len(peopleSet)
		}
		if sessionsSet, exists := serviceSessions[eventSource]; exists {
			service.SessionsCount = len(sessionsSet)
		}
		if accountsSet, exists := serviceAccounts[eventSource]; exists {
			service.AccountsCount = len(accountsSet)
		}
	}

	for resourceID, resource := range resourceMap {
		if peopleSet, exists := resourcePeople[resourceID]; exists {
			resource.PeopleCount = len(peopleSet)
		}
		if sessionsSet, exists := resourceSessions[resourceID]; exists {
			resource.SessionsCount = len(sessionsSet)
		}
	}

	// Update counts for people based on unique sets
	for email, person := range people {
		if accountsSet, exists := personAccounts[email]; exists {
			person.AccountsCount = len(accountsSet)
		}
		if rolesSet, exists := personRoles[email]; exists {
			person.RolesCount = len(rolesSet)
		}
		if servicesSet, exists := personServices[email]; exists {
			person.ServicesCount = len(servicesSet)
		}
		if resourcesSet, exists := personResources[email]; exists {
			person.ResourcesCount = len(resourcesSet)
		}
		if sessionsSet, exists := personSessions[email]; exists {
			person.SessionsCount = len(sessionsSet)
		}
	}

	// Update counts for sessions based on unique sets
	for sessionID, sess := range sessions {
		if servicesSet, exists := sessionServices[sessionID]; exists {
			sess.ServicesCount = len(servicesSet)
		}
		if resourcesSet, exists := sessionResources[sessionID]; exists {
			sess.ResourcesCount = len(resourcesSet)
		}
	}

	// Update counts for accounts based on unique sets
	for accountID, account := range accounts {
		if peopleSet, exists := accountPeople[accountID]; exists {
			account.PeopleCount = len(peopleSet)
		}
		if sessionsSet, exists := accountSessions[accountID]; exists {
			account.SessionsCount = len(sessionsSet)
		}
		if rolesSet, exists := accountRoles[accountID]; exists {
			account.RolesCount = len(rolesSet)
		}
		if servicesSet, exists := accountServices[accountID]; exists {
			account.ServicesCount = len(servicesSet)
		}
		if resourcesSet, exists := accountResources[accountID]; exists {
			account.ResourcesCount = len(resourcesSet)
		}
	}

	// Write aggregated data to DynamoDB (with customerId field)
	for _, role := range roles {
		// Set customerId field
		role.CustomerID = customerID
		// Log role details before write attempt with actual event names
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
		if err := ddblib.WriteRoleToDynamoDB(ctx, ddbClient, rolesAggregatedTable, role); err != nil {
			log.Printf("ERROR: Failed to write role: %v", err)
		}
	}

	for _, service := range services {
		// Set customerId field
		service.CustomerID = customerID
		if err := ddblib.WriteServiceToDynamoDB(ctx, ddbClient, servicesAggregatedTable, service); err != nil {
			log.Printf("ERROR: Failed to write service: %v", err)
		}
	}

	for _, resource := range resourceMap {
		// Set customerId field
		resource.CustomerID = customerID
		if err := ddblib.WriteResourceToDynamoDB(ctx, ddbClient, resourcesAggregatedTable, resource); err != nil {
			log.Printf("ERROR: Failed to write resource: %v", err)
		}
	}

	// Log summary of what was found
	log.Printf("=== Aggregation Summary ===")
	log.Printf("Found %d unique people, %d sessions, %d roles, %d services, %d resources, %d accounts",
		len(people), len(sessions), len(roles), len(services), len(resourceMap), len(accounts))

	// Count session types
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

	// Log details about each session
	for _, sess := range sessions {
		log.Printf("Session: type=%s email=%s role=%s account=%s events=%d startTime=%s",
			sess.SessionType, sess.PersonEmail, sess.RoleName, sess.AccountID, sess.EventsCount, sess.StartTime)
	}

	// Log roles found
	for _, role := range roles {
		log.Printf("Role: arn=%s account=%s events=%d", role.ARN, role.AccountID, role.TotalEvents)
	}

	// Log accounts found
	for _, account := range accounts {
		log.Printf("Account: id=%s events=%d people=%d sessions=%d", account.AccountID, account.EventsCount, account.PeopleCount, account.SessionsCount)
	}

	// Write new noun-based aggregations
	for _, person := range people {
		// Set customerId field
		person.CustomerID = customerID
		if err := ddblib.WritePersonToDynamoDB(ctx, ddbClient, peopleAggregatedTable, person); err != nil {
			log.Printf("ERROR: Failed to write person: %v", err)
		}
	}

	for _, sess := range sessions {
		// Calculate duration before writing
		if sess.StartTime != "" && sess.EndTime != "" {
			startTime, _ := time.Parse(time.RFC3339, sess.StartTime)
			endTime, _ := time.Parse(time.RFC3339, sess.EndTime)
			sess.DurationMinutes = int(endTime.Sub(startTime).Minutes())
		}

		// Set customerId field
		sess.CustomerID = customerID
		if err := ddblib.WriteSessionToDynamoDB(ctx, ddbClient, sessionsAggregatedTable, sess); err != nil {
			log.Printf("ERROR: Failed to write session: %v", err)
		}
	}

	for _, account := range accounts {
		// Set customerId field
		account.CustomerID = customerID
		if err := ddblib.WriteAccountToDynamoDB(ctx, ddbClient, accountsAggregatedTable, account); err != nil {
			log.Printf("ERROR: Failed to write account: %v", err)
		}
	}

	log.Printf("Processed %d roles, %d services, %d resources, %d people, %d sessions, %d accounts",
		len(roles), len(services), len(resourceMap), len(people), len(sessions), len(accounts))
	return nil
}

// processRoleEvent aggregates an event for a role
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

	// Check if this is an AccessDenied error
	isAccessDenied := session.IsAccessDeniedError(event.ErrorCode)

	// Track event names with service prefix (format: "eventSource:eventName")
	eventKey := event.EventSource + ":" + event.EventName

	if isAccessDenied {
		// Extract policy info from error message (AWS Jan 2026 update includes policy ARNs)
		policyInfo := session.ExtractPolicyInfo(event.ErrorMessage)
		if policyInfo.PolicyARN != "" {
			log.Printf("ROLE_ACCESS_DENIED: role=%s event=%s errorCode=%s policy_arn=%s policy_type=%s errorMessage=%q", roleARN, eventKey, event.ErrorCode, policyInfo.PolicyARN, policyInfo.PolicyType, event.ErrorMessage)
		} else {
			log.Printf("ROLE_ACCESS_DENIED: role=%s event=%s errorCode=%s errorMessage=%q", roleARN, eventKey, event.ErrorCode, event.ErrorMessage)
		}

		// Track denied events separately
		role.TotalDeniedEvents++
		role.TopDeniedEventNames[eventKey]++

		// Track denied resource accesses
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
					service := event.EventSource
					if len(parts) > 0 {
						service = parts[0] + ".amazonaws.com"
					}

					role.DeniedResourceAccesses = append(role.DeniedResourceAccesses, types.ResourceAccessItem{
						Resource:     resource,
						Service:      service,
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
		// Track successful events (existing logic)
		role.TotalEvents++
		role.ServicesCount[event.EventSource]++
		role.TopEventNames[eventKey]++

		// Track resources and resource accesses
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
				service := event.EventSource
				if len(parts) > 0 {
					service = parts[0] + ".amazonaws.com"
				}

				role.ResourceAccesses = append(role.ResourceAccesses, types.ResourceAccessItem{
					Resource:  resource,
					Service:   service,
					EventName: event.EventName,
					Count:     1,
				})
			}
		}
	}

	role.LastSeen = eventDate

	return nil
}

// processServiceEvent aggregates an event for a service
func processServiceEvent(serviceMap map[string]*types.DynamoDBService, event types.CloudTrailRecord, roleARN string, eventDate string) error {
	eventSource := event.EventSource
	service, exists := serviceMap[eventSource]
	if !exists {
		service = &types.DynamoDBService{
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
		serviceMap[eventSource] = service
	}

	// Check if this is an AccessDenied error
	isAccessDenied := session.IsAccessDeniedError(event.ErrorCode)

	if isAccessDenied {
		service.TotalDeniedEvents++
		service.TopDeniedEventNames[event.EventName]++
	} else {
		service.TotalEvents++
		service.TopEventNames[event.EventName]++
	}

	service.LastSeen = eventDate

	// Track roles using this service
	if roleARN != "" {
		if service.RolesUsing == nil {
			service.RolesUsing = []string{}
		}

		found := false
		for _, existingRole := range service.RolesUsing {
			if existingRole == roleARN {
				found = true
				break
			}
		}
		if !found {
			service.RolesUsing = append(service.RolesUsing, roleARN)
		}
	}

	return nil
}

// findMatchingCloudTrailResource attempts to match a simplified resource identifier
// with an entry in the CloudTrail Resources array
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

// processResourceEvent aggregates an event for a resource
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

// handler processes CloudTrail management events delivered by EventBridge
func handler(ctx context.Context, event json.RawMessage) error {
	log.Printf("FULL_EVENT_RECEIVED: %s", string(event))

	// Try to parse as direct S3 event first
	var s3Event events.S3Event
	if err := json.Unmarshal(event, &s3Event); err == nil && len(s3Event.Records) > 0 {
		log.Printf("Processing direct S3 event with %d records", len(s3Event.Records))
		return processS3Event(ctx, s3Event)
	}

	// Try to parse as EventBridge event
	var ebEvent types.EventBridgeS3Event
	if err := json.Unmarshal(event, &ebEvent); err == nil && ebEvent.Source == "aws.s3" {
		log.Printf("Processing EventBridge S3 event: detail-type=%s", ebEvent.DetailType)

		bucket, _ := ebEvent.Detail["bucket"].(map[string]interface{})
		bucketName, _ := bucket["name"].(string)

		object, _ := ebEvent.Detail["object"].(map[string]interface{})
		objectKey, _ := object["key"].(string)

		log.Printf("EventBridge S3 event: bucket=%s, key=%s", bucketName, objectKey)

		s3Event := events.S3Event{
			Records: []events.S3EventRecord{
				{
					AWSRegion: ebEvent.Region,
					S3: events.S3Entity{
						Bucket: events.S3Bucket{
							Name: bucketName,
						},
						Object: events.S3Object{
							Key: objectKey,
						},
					},
				},
			},
		}

		return processS3Event(ctx, s3Event)
	}

	log.Printf("Unknown event format, skipping")
	return nil
}

func processS3Event(ctx context.Context, event events.S3Event) error {
	// Load AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	ddbClient := dynamodb.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	return handleS3(ctx, ddbClient, s3Client, event)
}

func handleS3(ctx context.Context, ddbClient *dynamodb.Client, s3Client *s3.Client, event events.S3Event) error {
	customerID := defaultCustomerID
	log.Printf("Processing events for customer: %s", customerID)

	for _, record := range event.Records {
		bucket := record.S3.Bucket.Name
		key := record.S3.Object.Key

		log.Printf("S3 event: bucket=%s, key=%s", bucket, key)

		// Skip CloudTrail Insight, Digest, and Aggregated files (only process regular CloudTrail logs)
		if strings.Contains(key, "/CloudTrail-Insight/") ||
			strings.Contains(key, "/CloudTrail-Digest/") ||
			strings.Contains(key, "/CloudTrail-Aggregated/") {
			log.Printf("Skipping non-event CloudTrail file: %s", key)
			continue
		}

		// Download and decompress CloudTrail log file
		result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return fmt.Errorf("failed to get S3 object: %w", err)
		}
		defer result.Body.Close()

		// Parse CloudTrail log (handles gzip decompression and JSON parsing)
		cloudTrailLog, err := parser.ParseCloudTrailLog(result.Body)
		if err != nil {
			return err
		}

		log.Printf("Processing %d CloudTrail events from S3: %s/%s", len(cloudTrailLog.Records), bucket, key)

		// Process all events with customer ID
		if err := ProcessRolesServicesResources(ctx, ddbClient, customerID, cloudTrailLog.Records); err != nil {
			return fmt.Errorf("failed to process CloudTrail events: %w", err)
		}

		log.Printf("SUCCESS: Processed %d events from S3", len(cloudTrailLog.Records))
	}

	return nil
}

func main() {
	lambda.Start(handler)
}
