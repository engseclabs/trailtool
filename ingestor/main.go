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

// NOTE: All type definitions moved to types.go
// NOTE: IsAWSIP and IsAWSUserAgent functions moved to session.go
// NOTE: IsAccessDeniedError, PolicyInfo, and ExtractPolicyInfo moved to session.go
// NOTE: ExtractEmailFromPrincipalID moved to session.go

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}


// NOTE: ExtractRoleIDFromPrincipalID, ExtractRoleNameFromARN, ExtractAccountIDFromARN,
// IsIdentityCenterRole, NormalizeUserAgent, ClassifySessionType, IsClickOpsOperation,
// IsValidSourceIP, IsValidUserAgent, GetRoleARN, GetSessionCreationTime, GenerateSessionKey
// all moved to session.go

// NOTE: Resource extraction functions moved to resources.go:
// - ExtractResources
// - normalizeResourceFromARN
// - extractS3Bucket, extractLambdaFunction, extractDynamoTable, extractEC2Instance
// - extractIAMResource, extractCloudFormationStack, extractControlTowerResource
// - extractRDSResource, extractECRRepository, extractECSResource, extractSQSQueue
// - extractSNSTopic, extractKMSKey, extractSecret, extractLogGroup
// - extractEventRule, extractStateMachine, extractRestApi, extractHostedZone
// - extractCloudFrontDistribution, GetServiceDisplayName, GetServiceCategory






// processPersonEvent tracks aggregated data for a person
func processPersonEvent(people map[string]*DynamoDBPerson, email, accountID, roleARN, eventSource, eventDate string) {
	person, exists := people[email]
	if !exists {
		person = &DynamoDBPerson{
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
func processSessionEvent(sessions map[string]*DynamoDBSessionAggregated, people map[string]*DynamoDBPerson, customerID, sessionMapKey, truncatedSessionID, email, roleID, accountID, roleARN, roleName, sessionCreationTime, eventTime, sourceIP, userAgent, eventSource, eventName, errorCode, errorMessage string, resources []string, eventDate string) {
	session, exists := sessions[sessionMapKey]
	if !exists {
		// Look up person display name
		displayName := ""
		if person, personExists := people[email]; personExists {
			displayName = person.DisplayName
		}

		// Classify session type based on first user agent seen
		sessionType := ClassifySessionType(userAgent)

		// Skip sessions with unrecognized user agents - don't create or merge them
		if sessionType == "" {
			log.Printf("SKIPPED: Unrecognized session type - email:%s role:%s userAgent:%s", email, roleID, userAgent)
			return
		}

		session = &DynamoDBSessionAggregated{
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
			ResourceAccesses:        []ResourceAccess{}, // Will be populated during event processing
			DeniedEventCount:        0,
			DeniedEventCounts:       make(map[string]int),
			DeniedResourcesAccessed: make(map[string]int),
			DeniedResourceAccesses:  []ResourceAccess{},
			DeniedEventAccesses:     []EventAccess{},
		}
		sessions[sessionMapKey] = session
	}

	session.EndTime = eventTime

	// Check if this is an AccessDenied error
	isAccessDenied := IsAccessDeniedError(errorCode)

	// Track event counts (flattened eventSource:eventName)
	eventKey := fmt.Sprintf("%s:%s", eventSource, eventName)

	if isAccessDenied {
		// Extract policy info from error message (AWS Jan 2026 update includes policy ARNs)
		policyInfo := ExtractPolicyInfo(errorMessage)
		if policyInfo.PolicyARN != "" {
			log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s policy_arn=%s policy_type=%s errorMessage=%q", sessionMapKey, eventKey, errorCode, policyInfo.PolicyARN, policyInfo.PolicyType, errorMessage)
		} else {
			log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s errorMessage=%q", sessionMapKey, eventKey, errorCode, errorMessage)
		}
		// Track denied events separately
		session.DeniedEventCount++
		session.DeniedEventCounts[eventKey]++

		if len(resources) > 0 {
			// Track denied resources accessed (both old format and new detailed format)
			for _, resource := range resources {
				session.DeniedResourcesAccessed[resource]++

				// Track detailed denied resource access (service + event + resource + count + policy info)
				// Find existing ResourceAccess or create new one
				// Note: We match on resource+service+event+policy to track denials from different policies separately
				found := false
				for i := range session.DeniedResourceAccesses {
					if session.DeniedResourceAccesses[i].Resource == resource &&
						session.DeniedResourceAccesses[i].Service == eventSource &&
						session.DeniedResourceAccesses[i].EventName == eventName &&
						session.DeniedResourceAccesses[i].PolicyARN == policyInfo.PolicyARN {
						session.DeniedResourceAccesses[i].Count++
						found = true
						break
					}
				}
				if !found {
					session.DeniedResourceAccesses = append(session.DeniedResourceAccesses, ResourceAccess{
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
			// Find existing EventAccess or create new one
			// Note: We match on service+event+policy to track denials from different policies separately
			found := false
			for i := range session.DeniedEventAccesses {
				if session.DeniedEventAccesses[i].Service == eventSource &&
					session.DeniedEventAccesses[i].EventName == eventName &&
					session.DeniedEventAccesses[i].PolicyARN == policyInfo.PolicyARN {
					session.DeniedEventAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				session.DeniedEventAccesses = append(session.DeniedEventAccesses, EventAccess{
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
		session.EventsCount++
		session.EventCounts[eventKey]++

		// Track resources accessed (both old format and new detailed format)
		for _, resource := range resources {
			session.ResourcesAccessed[resource]++

			// Track detailed resource access (service + event + resource + count)
			// Find existing ResourceAccess or create new one
			found := false
			for i := range session.ResourceAccesses {
				if session.ResourceAccesses[i].Resource == resource &&
					session.ResourceAccesses[i].Service == eventSource &&
					session.ResourceAccesses[i].EventName == eventName {
					session.ResourceAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				session.ResourceAccesses = append(session.ResourceAccesses, ResourceAccess{
					Resource:  resource,
					Service:   eventSource,
					EventName: eventName,
					Count:     1,
				})
			}
		}
	}

	// Track ClickOps operations (web console create/modify operations)
	if !isAccessDenied && session.SessionType == "web-console" && IsClickOpsOperation(eventName) {
		session.ClickOpsEventCount++
		if session.ClickOpsEventCounts == nil {
			session.ClickOpsEventCounts = make(map[string]int)
		}
		session.ClickOpsEventCounts[eventName]++
	}

	// Add source IP if not already present and it's a valid user IP
	if sourceIP != "" && IsValidSourceIP(sourceIP) {
		found := false
		for _, ip := range session.SourceIPs {
			if ip == sourceIP {
				found = true
				break
			}
		}
		if !found {
			session.SourceIPs = append(session.SourceIPs, sourceIP)
		}
	}

	// Add user agent if not already present and it's a valid user agent (not service-to-service)
	if userAgent != "" && IsValidUserAgent(userAgent) {
		found := false
		for _, ua := range session.UserAgents {
			if ua == userAgent {
				found = true
				break
			}
		}
		if !found {
			session.UserAgents = append(session.UserAgents, userAgent)
		}
	}

	// Duration will be computed at end
}

// processAccountEvent tracks aggregated data for an account
func processAccountEvent(accounts map[string]*DynamoDBAccount, accountID, email, sessionID, roleARN, eventSource, eventDate string) {
	account, exists := accounts[accountID]
	if !exists {
		account = &DynamoDBAccount{
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
func ProcessRolesServicesResources(ctx context.Context, ddbClient *dynamodb.Client, customerID string, events []CloudTrailRecord) error {
	log.Printf("=== Processing Noun-Based Aggregation ===")
	log.Printf("Processing %d events for aggregation (customer: %s)", len(events), customerID)

	// Aggregation maps for all nouns
	roles := make(map[string]*DynamoDBRole)
	services := make(map[string]*DynamoDBService)
	resources := make(map[string]*DynamoDBResource)
	people := make(map[string]*DynamoDBPerson)
	sessions := make(map[string]*DynamoDBSessionAggregated)
	accounts := make(map[string]*DynamoDBAccount)

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
	for _, event := range events {
		eventTime := event.EventTime
		eventDate := eventTime[:10] // Extract date part YYYY-MM-DD

		// Skip synthetic sessions that aren't real human activity
		if strings.Contains(event.UserIdentity.PrincipalID, "ConfigResourceCompositionSession") {
			continue
		}

		// Extract core identifiers for this event
		email := ExtractEmailFromPrincipalID(event.UserIdentity.PrincipalID)
		roleARN := GetRoleARN(event)

		// Fallback to UserIdentity.ARN if SessionContext ARN is not available
		if roleARN == "" {
			roleARN = event.UserIdentity.ARN
		}

		roleID := ExtractRoleIDFromPrincipalID(event.UserIdentity.PrincipalID)

		// Try to get account ID from multiple sources (fallback chain)
		accountID := ExtractAccountIDFromARN(roleARN)
		if accountID == "" {
			accountID = event.UserIdentity.AccountID
		}
		if accountID == "" && event.UserIdentity.ARN != "" {
			accountID = ExtractAccountIDFromARN(event.UserIdentity.ARN)
		}

		// Build unique in-memory key (includes creation time) and truncated stable ID for storage.
		// If there's an email, we track this as a session (person-initiated activity)
		var sessionMapKey, truncatedSessionID, sessionCreationTime string
		if email != "" && roleID != "" {
			// Normalize user agent by stripping brackets
			normalizedUserAgent := NormalizeUserAgent(event.UserAgent)

			// Try time-based windowing for CLI sessions first
			cliSessionKey, cliStartTime := GenerateSessionKey(email, roleID, normalizedUserAgent, eventTime)

			if cliSessionKey != "" {
				// CLI session: use 4-hour time window
				sessionMapKey = cliSessionKey
				sessionCreationTime = cliStartTime
				truncatedSessionID = fmt.Sprintf("%s:%s", email, roleID)
			} else {
				// Console session: use IAM creation time
				sessionCreationTime = GetSessionCreationTime(event)
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
			normalizedUserAgent := NormalizeUserAgent(event.UserAgent)
			resourceList := ExtractResources(event)
			processSessionEvent(sessions, people, customerID, sessionMapKey, truncatedSessionID, email, roleID, accountID, roleARN, ExtractRoleNameFromARN(roleARN),
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
		resourceList := ExtractResources(event)
		for _, resource := range resourceList {
			if err := processResourceEvent(resources, event, resource, accountID, eventDate); err != nil {
				log.Printf("WARNING: Failed to process resource event: %v", err)
			}

			// Track ClickOps operations (web console create/modify operations)
			if sessionMapKey != "" {
				// Check if this is a web-console session and a ClickOps operation
				if session, exists := sessions[sessionMapKey]; exists {
					if session.SessionType == "web-console" && IsClickOpsOperation(event.EventName) {
						// Get or create the resource entry
						if resourceEntry, exists := resources[resource]; exists {
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
								resourceEntry.ClickOpsAccesses = append(resourceEntry.ClickOpsAccesses, ClickOpsAccess{
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

	for resourceID, resource := range resources {
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
	for sessionID, session := range sessions {
		if servicesSet, exists := sessionServices[sessionID]; exists {
			session.ServicesCount = len(servicesSet)
		}
		if resourcesSet, exists := sessionResources[sessionID]; exists {
			session.ResourcesCount = len(resourcesSet)
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
		if err := writeRoleToDynamoDB(ctx, ddbClient, role); err != nil {
			log.Printf("ERROR: Failed to write role: %v", err)
		}
	}

	for _, service := range services {
		// Set customerId field
		service.CustomerID = customerID
		if err := writeServiceToDynamoDB(ctx, ddbClient, service); err != nil {
			log.Printf("ERROR: Failed to write service: %v", err)
		}
	}

	for _, resource := range resources {
		// Set customerId field
		resource.CustomerID = customerID
		if err := writeResourceToDynamoDB(ctx, ddbClient, resource); err != nil {
			log.Printf("ERROR: Failed to write resource: %v", err)
		}
	}

	// Log summary of what was found
	log.Printf("=== Aggregation Summary ===")
	log.Printf("Found %d unique people, %d sessions, %d roles, %d services, %d resources, %d accounts",
		len(people), len(sessions), len(roles), len(services), len(resources), len(accounts))

	// Count session types
	cliSessions := 0
	webSessions := 0
	for _, session := range sessions {
		if session.SessionType == "cli-sdk" {
			cliSessions++
		} else if session.SessionType == "web-console" {
			webSessions++
		}
	}
	log.Printf("Session breakdown: %d CLI/SDK sessions, %d web console sessions", cliSessions, webSessions)

	// Log details about each session
	for _, session := range sessions {
		log.Printf("Session: type=%s email=%s role=%s account=%s events=%d startTime=%s",
			session.SessionType, session.PersonEmail, session.RoleName, session.AccountID, session.EventsCount, session.StartTime)
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
		if err := writePersonToDynamoDB(ctx, ddbClient, person); err != nil {
			log.Printf("ERROR: Failed to write person: %v", err)
		}
	}

	for _, session := range sessions {
		// Calculate duration before writing
		if session.StartTime != "" && session.EndTime != "" {
			startTime, _ := time.Parse(time.RFC3339, session.StartTime)
			endTime, _ := time.Parse(time.RFC3339, session.EndTime)
			session.DurationMinutes = int(endTime.Sub(startTime).Minutes())
		}

		// Set customerId field
		session.CustomerID = customerID
		if err := writeSessionToDynamoDB(ctx, ddbClient, session); err != nil {
			log.Printf("ERROR: Failed to write session: %v", err)
		}
	}

	for _, account := range accounts {
		// Set customerId field
		account.CustomerID = customerID
		if err := writeAccountToDynamoDB(ctx, ddbClient, account); err != nil {
			log.Printf("ERROR: Failed to write account: %v", err)
		}
	}

	log.Printf("Processed %d roles, %d services, %d resources, %d people, %d sessions, %d accounts",
		len(roles), len(services), len(resources), len(people), len(sessions), len(accounts))
	return nil
}

// processRoleEvent aggregates an event for a role
func processRoleEvent(roles map[string]*DynamoDBRole, event CloudTrailRecord, roleARN string, eventDate string) error {
	role, exists := roles[roleARN]
	if !exists {
		role = &DynamoDBRole{
			ARN:                    roleARN,
			Name:                   ExtractRoleNameFromARN(roleARN),
			AccountID:              ExtractAccountIDFromARN(roleARN),
			FirstSeen:              eventDate,
			LastSeen:               eventDate,
			TotalEvents:            0,
			ServicesCount:          make(map[string]int),
			ResourcesCount:         make(map[string]int),
			TopEventNames:          make(map[string]int),
			ResourceAccesses:       []ResourceAccessItem{},
			TotalDeniedEvents:      0,
			TopDeniedEventNames:    make(map[string]int),
			DeniedResourceAccesses: []ResourceAccessItem{},
			DeniedEventAccesses:    []EventAccessItem{},
		}
		roles[roleARN] = role
	}

	// Check if this is an AccessDenied error
	isAccessDenied := IsAccessDeniedError(event.ErrorCode)

	// Track event names with service prefix (format: "eventSource:eventName")
	// This matches the session EventCounts format and enables IAM action mapping
	eventKey := event.EventSource + ":" + event.EventName

	if isAccessDenied {
		// Extract policy info from error message (AWS Jan 2026 update includes policy ARNs)
		policyInfo := ExtractPolicyInfo(event.ErrorMessage)
		if policyInfo.PolicyARN != "" {
			log.Printf("ROLE_ACCESS_DENIED: role=%s event=%s errorCode=%s policy_arn=%s policy_type=%s errorMessage=%q", roleARN, eventKey, event.ErrorCode, policyInfo.PolicyARN, policyInfo.PolicyType, event.ErrorMessage)
		} else {
			log.Printf("ROLE_ACCESS_DENIED: role=%s event=%s errorCode=%s errorMessage=%q", roleARN, eventKey, event.ErrorCode, event.ErrorMessage)
		}

		// Track denied events separately
		role.TotalDeniedEvents++
		role.TopDeniedEventNames[eventKey]++

		// Track denied resource accesses
		resourceList := ExtractResources(event)
		if len(resourceList) > 0 {
			for _, resource := range resourceList {
				// Find or create the denied resource access entry
				// Note: We match on resource+event+policy to track denials from different policies separately
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
					// Extract service from resource identifier (format: "service:type:name")
					parts := strings.Split(resource, ":")
					service := event.EventSource
					if len(parts) > 0 {
						service = parts[0] + ".amazonaws.com"
					}

					role.DeniedResourceAccesses = append(role.DeniedResourceAccesses, ResourceAccessItem{
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
			// Track denied events without specific resources
			// Find or create the denied event access entry
			// Note: We match on service+event+policy to track denials from different policies separately
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
				role.DeniedEventAccesses = append(role.DeniedEventAccesses, EventAccessItem{
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
		resourceList := ExtractResources(event)
		for _, resource := range resourceList {
			role.ResourcesCount[resource]++

			// Track resource access details (resource + service + event)
			// Find or create the resource access entry
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
				// Extract service from resource identifier (format: "service:type:name")
				parts := strings.Split(resource, ":")
				service := event.EventSource
				if len(parts) > 0 {
					service = parts[0] + ".amazonaws.com"
				}

				role.ResourceAccesses = append(role.ResourceAccesses, ResourceAccessItem{
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
func processServiceEvent(services map[string]*DynamoDBService, event CloudTrailRecord, roleARN string, eventDate string) error {
	eventSource := event.EventSource
	service, exists := services[eventSource]
	if !exists {
		service = &DynamoDBService{
			EventSource:         eventSource,
			DisplayName:         GetServiceDisplayName(eventSource),
			Category:            GetServiceCategory(eventSource),
			FirstSeen:           eventDate,
			LastSeen:            eventDate,
			TotalEvents:         0,
			TopEventNames:       make(map[string]int),
			TotalDeniedEvents:   0,
			TopDeniedEventNames: make(map[string]int),
		}
		services[eventSource] = service
	}

	// Check if this is an AccessDenied error
	isAccessDenied := IsAccessDeniedError(event.ErrorCode)

	if isAccessDenied {
		// Track denied events separately
		service.TotalDeniedEvents++
		service.TopDeniedEventNames[event.EventName]++
	} else {
		// Track successful events (existing logic)
		service.TotalEvents++
		service.TopEventNames[event.EventName]++
	}

	service.LastSeen = eventDate

	// Track roles using this service
	if roleARN != "" {
		// Add role to set (using map as set)
		if service.RolesUsing == nil {
			service.RolesUsing = []string{}
		}

		// Check if role already in list
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
// (e.g., "lambda:function:trailtool-ingestor") with an entry in the CloudTrail Resources array
func findMatchingCloudTrailResource(event CloudTrailRecord, resourceIdentifier string) *CloudTrailResource {
	if len(event.Resources) == 0 {
		return nil
	}

	// For events with a single resource, return it
	if len(event.Resources) == 1 {
		return &event.Resources[0]
	}

	// For events with multiple resources, try to match by resource name/identifier
	// Extract the resource name from the identifier (e.g., "trailtool-ingestor" from "lambda:function:trailtool-ingestor")
	parts := strings.Split(resourceIdentifier, ":")
	if len(parts) >= 3 {
		resourceName := parts[2]
		// Try to find a CloudTrail resource whose ARN contains this name
		for i := range event.Resources {
			if strings.Contains(event.Resources[i].ARN, resourceName) {
				return &event.Resources[i]
			}
		}
	}

	// If no match found, return the first resource as a fallback
	return &event.Resources[0]
}

// processResourceEvent aggregates an event for a resource
func processResourceEvent(resources map[string]*DynamoDBResource, event CloudTrailRecord, resourceIdentifier string, accountID string, eventDate string) error {
	resource, exists := resources[resourceIdentifier]
	if !exists {
		parts := strings.Split(resourceIdentifier, ":")
		resourceType := "unknown"
		resourceName := resourceIdentifier

		if len(parts) >= 3 {
			resourceType = parts[0] + ":" + parts[1]
			resourceName = parts[2]
		}

		// Try to extract account ID and ARN from the CloudTrail Resources array
		ctResource := findMatchingCloudTrailResource(event, resourceIdentifier)
		resourceARN := ""
		resourceAccountID := accountID // Default to UserIdentity account

		if ctResource != nil {
			// Use the resource's actual account ID if available
			if ctResource.AccountID != "" {
				resourceAccountID = ctResource.AccountID
			}
			// Capture the full ARN
			if ctResource.ARN != "" {
				resourceARN = ctResource.ARN
			}
		}

		resource = &DynamoDBResource{
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
		resources[resourceIdentifier] = resource
	}

	// Check if this is an AccessDenied error
	isAccessDenied := IsAccessDeniedError(event.ErrorCode)

	if isAccessDenied {
		// Track denied events separately
		resource.TotalDeniedEvents++
		resource.TopDeniedEventNames[event.EventName]++
	} else {
		// Track successful events (existing logic)
		resource.TotalEvents++
		resource.TopEventNames[event.EventName]++
	}

	resource.LastSeen = eventDate

	// Track roles using this resource
	if roleARN := GetRoleARN(event); roleARN != "" {
		if resource.RolesUsing == nil {
			resource.RolesUsing = []string{}
		}

		// Check if role already in list
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

	// Track services using this resource
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

// NOTE: DynamoDB write and merge functions moved to dynamodb.go:
// - writeRoleToDynamoDB, mergeRoleAggregated, mergeResourceAccessItems, mergeEventAccessItems
// - writeServiceToDynamoDB, writeResourceToDynamoDB, writePersonToDynamoDB
// - writeSessionToDynamoDB, mergeSessionAggregated, mergeUniqueStrings, mergeIntMaps
// - countUniqueServices, mergeResourceAccesses, mergeEventAccesses, writeAccountToDynamoDB

// handler processes CloudTrail management events delivered by EventBridge
// EventBridge delivers events with detail-type "AWS API Call via CloudTrail"
// Each invocation represents a single API call (not batched like S3 logs)
// NOTE: EventBridgeS3Event type moved to types.go

func handler(ctx context.Context, event json.RawMessage) error {
	log.Printf("FULL_EVENT_RECEIVED: %s", string(event))

	// Try to parse as direct S3 event first
	var s3Event events.S3Event
	if err := json.Unmarshal(event, &s3Event); err == nil && len(s3Event.Records) > 0 {
		log.Printf("Processing direct S3 event with %d records", len(s3Event.Records))
		return processS3Event(ctx, s3Event)
	}

	// Try to parse as EventBridge event
	var ebEvent EventBridgeS3Event
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
		cloudTrailLog, err := ParseCloudTrailLog(result.Body)
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
