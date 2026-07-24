// Per-event aggregation for the non-session nouns: people, accounts,
// roles, services, and resources.
package aggregator

import (
	"log"
	"strings"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/resources"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

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
func processRoleEvent(roles map[string]*types.DynamoDBRole, event types.CloudTrailRecord, roleARN string, eventDate string) {
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
}

// processServiceEvent aggregates an event for a service.
func processServiceEvent(serviceMap map[string]*types.DynamoDBService, event types.CloudTrailRecord, roleARN string, resourceList []string, eventDate string) {
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
	for _, resource := range resourceList {
		appendUnique(&svc.ResourcesUsed, resource)
	}
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
func processResourceEvent(resourceMap map[string]*types.DynamoDBResource, event types.CloudTrailRecord, resourceIdentifier string, accountID string, eventDate string) {
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
}
