// Package dynamodb contains DynamoDB write and merge operations for the ingestor.
package dynamodb

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// WriteRoleToDynamoDB writes or updates a role in DynamoDB using read-merge-write pattern
func WriteRoleToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, role *types.DynamoDBRole) error {
	// Query for existing role with the same customerId and arn
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": &ddbtypes.AttributeValueMemberS{Value: role.CustomerID},
			"arn":        &ddbtypes.AttributeValueMemberS{Value: role.ARN},
		},
	}

	getResult, err := ddbClient.GetItem(ctx, getInput)
	if err != nil {
		log.Printf("WARNING: Failed to get existing role: %v", err)
		// Continue with normal write if get fails
	} else if getResult.Item != nil && len(getResult.Item) > 0 {
		// Role exists - merge it
		var existingRole types.DynamoDBRole
		if err := attributevalue.UnmarshalMap(getResult.Item, &existingRole); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing role: %v", err)
		} else {
			log.Printf("ROLE_MERGE: arn=%s existing_events=%d new_events=%d", role.ARN, existingRole.TotalEvents, role.TotalEvents)

			// Merge the roles
			merged := MergeRoleAggregated(&existingRole, role)

			// Write the merged role
			item, err := attributevalue.MarshalMap(merged)
			if err != nil {
				return fmt.Errorf("failed to marshal merged role: %w", err)
			}

			_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(tableName),
				Item:      item,
			})

			if err != nil {
				return fmt.Errorf("failed to write merged role: %w", err)
			}

			log.Printf("ROLE_MERGED: arn=%s total_events=%d (was %d, +%d) resource_accesses=%d denied_resource_accesses=%d",
				merged.ARN, merged.TotalEvents, existingRole.TotalEvents, role.TotalEvents,
				len(merged.ResourceAccesses), len(merged.DeniedResourceAccesses))

			return nil
		}
	}

	// No existing role - write as new
	log.Printf("ROLE_CREATE: arn=%s events=%d", role.ARN, role.TotalEvents)

	item, err := attributevalue.MarshalMap(role)
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// MergeRoleAggregated merges two DynamoDBRole records, combining their data
func MergeRoleAggregated(existing *types.DynamoDBRole, new *types.DynamoDBRole) *types.DynamoDBRole {
	// Use earlier first_seen and later last_seen
	firstSeen := existing.FirstSeen
	if new.FirstSeen < firstSeen {
		firstSeen = new.FirstSeen
	}
	lastSeen := existing.LastSeen
	if new.LastSeen > lastSeen {
		lastSeen = new.LastSeen
	}

	// Merge event counts and service/resource counts
	mergedTopEventNames := MergeIntMaps(existing.TopEventNames, new.TopEventNames)
	mergedServicesCount := MergeIntMaps(existing.ServicesCount, new.ServicesCount)
	mergedResourcesCount := MergeIntMaps(existing.ResourcesCount, new.ResourcesCount)
	mergedTopDeniedEventNames := MergeIntMaps(existing.TopDeniedEventNames, new.TopDeniedEventNames)

	// Merge resource accesses using similar logic to session merging
	mergedResourceAccesses := MergeResourceAccessItems(existing.ResourceAccesses, new.ResourceAccesses)
	mergedDeniedResourceAccesses := MergeResourceAccessItems(existing.DeniedResourceAccesses, new.DeniedResourceAccesses)
	mergedDeniedEventAccesses := MergeEventAccessItems(existing.DeniedEventAccesses, new.DeniedEventAccesses)

	// Build services_used and resources_used from merged counts
	servicesUsed := make([]string, 0, len(mergedServicesCount))
	for service := range mergedServicesCount {
		servicesUsed = append(servicesUsed, service)
	}
	resourcesUsed := make([]string, 0, len(mergedResourcesCount))
	for resource := range mergedResourcesCount {
		resourcesUsed = append(resourcesUsed, resource)
	}

	merged := &types.DynamoDBRole{
		CustomerID:             new.CustomerID,
		ARN:                    new.ARN,
		Name:                   new.Name,
		AccountID:              new.AccountID,
		FirstSeen:              firstSeen,
		LastSeen:               lastSeen,
		TotalEvents:            existing.TotalEvents + new.TotalEvents,
		ServicesCount:          mergedServicesCount,
		ResourcesCount:         mergedResourcesCount,
		TopEventNames:          mergedTopEventNames,
		ServicesUsed:           servicesUsed,
		ResourcesUsed:          resourcesUsed,
		ResourceAccesses:       mergedResourceAccesses,
		TotalDeniedEvents:      existing.TotalDeniedEvents + new.TotalDeniedEvents,
		TopDeniedEventNames:    mergedTopDeniedEventNames,
		DeniedResourceAccesses: mergedDeniedResourceAccesses,
		DeniedEventAccesses:    mergedDeniedEventAccesses,
		PeopleCount:            existing.PeopleCount + new.PeopleCount,
		SessionsCount:          existing.SessionsCount + new.SessionsCount,
		AccountsCount:          existing.AccountsCount + new.AccountsCount,
	}

	return merged
}

// MergeResourceAccessItems merges two ResourceAccessItem slices, combining counts for duplicates
func MergeResourceAccessItems(a, b []types.ResourceAccessItem) []types.ResourceAccessItem {
	// Use map to aggregate by unique combination of Resource+Service+EventName
	accessMap := make(map[string]*types.ResourceAccessItem)

	// Add all from first slice
	for _, ra := range a {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		accessMap[key] = &types.ResourceAccessItem{
			Resource:     ra.Resource,
			Service:      ra.Service,
			EventName:    ra.EventName,
			Count:        ra.Count,
			PolicyARN:    ra.PolicyARN,
			PolicyType:   ra.PolicyType,
			ErrorMessage: ra.ErrorMessage,
		}
	}

	// Merge from second slice
	for _, ra := range b {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ra.Count
			// Keep the first policy info we saw (could enhance to track multiple policies)
			if existing.PolicyARN == "" && ra.PolicyARN != "" {
				existing.PolicyARN = ra.PolicyARN
				existing.PolicyType = ra.PolicyType
				existing.ErrorMessage = ra.ErrorMessage
			}
		} else {
			accessMap[key] = &types.ResourceAccessItem{
				Resource:     ra.Resource,
				Service:      ra.Service,
				EventName:    ra.EventName,
				Count:        ra.Count,
				PolicyARN:    ra.PolicyARN,
				PolicyType:   ra.PolicyType,
				ErrorMessage: ra.ErrorMessage,
			}
		}
	}

	// Convert back to slice
	result := make([]types.ResourceAccessItem, 0, len(accessMap))
	for _, ra := range accessMap {
		result = append(result, *ra)
	}

	return result
}

// MergeEventAccessItems merges two EventAccessItem slices, combining counts for duplicates
func MergeEventAccessItems(a, b []types.EventAccessItem) []types.EventAccessItem {
	// Use map to aggregate by unique combination of Service+EventName+PolicyARN
	accessMap := make(map[string]*types.EventAccessItem)

	// Add all from first slice
	for _, ea := range a {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		accessMap[key] = &types.EventAccessItem{
			Service:      ea.Service,
			EventName:    ea.EventName,
			Count:        ea.Count,
			PolicyARN:    ea.PolicyARN,
			PolicyType:   ea.PolicyType,
			ErrorMessage: ea.ErrorMessage,
		}
	}

	// Merge from second slice
	for _, ea := range b {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ea.Count
			// Keep the first error message we saw (could enhance to track multiple messages)
			if existing.ErrorMessage == "" && ea.ErrorMessage != "" {
				existing.ErrorMessage = ea.ErrorMessage
			}
		} else {
			accessMap[key] = &types.EventAccessItem{
				Service:      ea.Service,
				EventName:    ea.EventName,
				Count:        ea.Count,
				PolicyARN:    ea.PolicyARN,
				PolicyType:   ea.PolicyType,
				ErrorMessage: ea.ErrorMessage,
			}
		}
	}

	// Convert back to slice
	result := make([]types.EventAccessItem, 0, len(accessMap))
	for _, ea := range accessMap {
		result = append(result, *ea)
	}

	return result
}

// WriteServiceToDynamoDB writes or updates a service in DynamoDB
func WriteServiceToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, service *types.DynamoDBService) error {
	service.RolesCount = len(service.RolesUsing)
	service.ResourcesCount = len(service.ResourcesUsed)

	item, err := attributevalue.MarshalMap(service)
	if err != nil {
		return fmt.Errorf("failed to marshal service: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// WriteResourceToDynamoDB writes or updates a resource in DynamoDB using read-merge-write pattern
func WriteResourceToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, resource *types.DynamoDBResource) error {
	resource.RolesCount = len(resource.RolesUsing)

	// Query for existing resource
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": &ddbtypes.AttributeValueMemberS{Value: resource.CustomerID},
			"identifier": &ddbtypes.AttributeValueMemberS{Value: resource.Identifier},
		},
	}

	getResult, err := ddbClient.GetItem(ctx, getInput)
	if err != nil {
		log.Printf("WARNING: Failed to get existing resource: %v", err)
	} else if getResult.Item != nil && len(getResult.Item) > 0 {
		var existingResource types.DynamoDBResource
		if err := attributevalue.UnmarshalMap(getResult.Item, &existingResource); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing resource: %v", err)
		} else {
			merged := MergeResourceAggregated(&existingResource, resource)
			item, err := attributevalue.MarshalMap(merged)
			if err != nil {
				return fmt.Errorf("failed to marshal merged resource: %w", err)
			}
			_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(tableName),
				Item:      item,
			})
			return err
		}
	}

	// No existing resource - write as new
	item, err := attributevalue.MarshalMap(resource)
	if err != nil {
		return fmt.Errorf("failed to marshal resource: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// MergeResourceAggregated merges two DynamoDBResource records, combining their data
func MergeResourceAggregated(existing *types.DynamoDBResource, incoming *types.DynamoDBResource) *types.DynamoDBResource {
	firstSeen := existing.FirstSeen
	if incoming.FirstSeen < firstSeen {
		firstSeen = incoming.FirstSeen
	}
	lastSeen := existing.LastSeen
	if incoming.LastSeen > lastSeen {
		lastSeen = incoming.LastSeen
	}

	// Use non-empty ARN
	arn := existing.ARN
	if arn == "" {
		arn = incoming.ARN
	}

	// Use non-unknown type
	resourceType := existing.Type
	if resourceType == "unknown" && incoming.Type != "unknown" {
		resourceType = incoming.Type
	}

	mergedClickOps := MergeClickOpsAccesses(existing.ClickOpsAccesses, incoming.ClickOpsAccesses)

	// Sum clickops counts, but recount from merged accesses to be accurate
	clickOpsCount := 0
	for _, access := range mergedClickOps {
		clickOpsCount += access.EventCount
	}

	merged := &types.DynamoDBResource{
		CustomerID:          incoming.CustomerID,
		Identifier:          incoming.Identifier,
		Type:                resourceType,
		ARN:                 arn,
		Name:                incoming.Name,
		AccountID:           incoming.AccountID,
		TotalEvents:         existing.TotalEvents + incoming.TotalEvents,
		RolesUsing:          MergeUniqueStrings(existing.RolesUsing, incoming.RolesUsing),
		ServicesUsed:        MergeUniqueStrings(existing.ServicesUsed, incoming.ServicesUsed),
		TopEventNames:       MergeIntMaps(existing.TopEventNames, incoming.TopEventNames),
		FirstSeen:           firstSeen,
		LastSeen:            lastSeen,
		TotalDeniedEvents:   existing.TotalDeniedEvents + incoming.TotalDeniedEvents,
		TopDeniedEventNames: MergeIntMaps(existing.TopDeniedEventNames, incoming.TopDeniedEventNames),
		PeopleCount:         existing.PeopleCount + incoming.PeopleCount,
		SessionsCount:       existing.SessionsCount + incoming.SessionsCount,
		ClickOpsAccesses:    mergedClickOps,
		ClickOpsCount:       clickOpsCount,
	}
	merged.RolesCount = len(merged.RolesUsing)

	return merged
}

// MergeClickOpsAccesses merges two slices of ClickOpsAccess, deduplicating by session+event
func MergeClickOpsAccesses(a, b []types.ClickOpsAccess) []types.ClickOpsAccess {
	type key struct {
		SessionID string
		EventName string
	}
	merged := make(map[key]*types.ClickOpsAccess)

	for i := range a {
		k := key{a[i].SessionID, a[i].EventName}
		cp := a[i]
		merged[k] = &cp
	}
	for i := range b {
		k := key{b[i].SessionID, b[i].EventName}
		if existing, ok := merged[k]; ok {
			existing.EventCount += b[i].EventCount
		} else {
			cp := b[i]
			merged[k] = &cp
		}
	}

	result := make([]types.ClickOpsAccess, 0, len(merged))
	for _, v := range merged {
		result = append(result, *v)
	}
	return result
}

// WritePersonToDynamoDB writes or updates a person in DynamoDB
func WritePersonToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, person *types.DynamoDBPerson) error {
	item, err := attributevalue.MarshalMap(person)
	if err != nil {
		return fmt.Errorf("failed to marshal person: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// WriteSessionToDynamoDB writes or updates a session in DynamoDB
// Uses composite sort key "startTime#sessionID" to disambiguate sessions from different
// roles that share the same time bucket (CLI/SDK) or timestamp (console)
func WriteSessionToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, session *types.DynamoDBSessionAggregated) error {
	// Build composite sort key: startTime#sessionID to disambiguate sessions from
	// different roles that fall in the same time bucket (CLI) or same second (console)
	session.SessionStart = session.StartTime + "#" + session.SessionID

	// Query for existing session with exact same customerId and session_start (composite key)
	queryInput := &dynamodb.QueryInput{
		TableName:              aws.String(tableName),
		KeyConditionExpression: aws.String("customerId = :cid AND session_start = :st"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":cid": &ddbtypes.AttributeValueMemberS{Value: session.CustomerID},
			":st":  &ddbtypes.AttributeValueMemberS{Value: session.SessionStart},
		},
		Limit: aws.Int32(1),
	}

	queryResult, err := ddbClient.Query(ctx, queryInput)
	if err != nil {
		log.Printf("WARNING: Failed to query for existing session: %v", err)
		// Continue with normal write if query fails
	} else if queryResult.Items != nil && len(queryResult.Items) > 0 {
		// Session exists - update it by merging events
		var existingSession types.DynamoDBSessionAggregated
		if err := attributevalue.UnmarshalMap(queryResult.Items[0], &existingSession); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing session: %v", err)
		} else {
			log.Printf("  Operation: UPDATE (session exists - adding events)")
			log.Printf("  Previous end_time: %s", existingSession.EndTime)
			log.Printf("  Previous event_count: %d", existingSession.EventsCount)

			// Merge the sessions - use latest end time and accumulate events
			merged := MergeSessionAggregated(&existingSession, session)

			// Write the merged session
			item, err := attributevalue.MarshalMap(merged)
			if err != nil {
				return fmt.Errorf("failed to marshal merged session: %w", err)
			}

			_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(tableName),
				Item:      item,
			})

			if err != nil {
				return fmt.Errorf("failed to write merged session: %w", err)
			}

			log.Printf("  Updated event_count: %d (was %d, +%d)", merged.EventsCount, existingSession.EventsCount, session.EventsCount)
			log.Printf("  Updated end_time: %s", merged.EndTime)
			log.Printf("  Updated duration: %d minutes", merged.DurationMinutes)

			return nil
		}
	}

	// No existing session - write as new
	log.Printf("  Operation: CREATE (new session)")
	log.Printf("  Session ID: %s", session.SessionID)
	log.Printf("  Start time (IAM): %s", session.StartTime)
	log.Printf("  Event count: %d", session.EventsCount)

	item, err := attributevalue.MarshalMap(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// MergeSessionAggregated merges two SessionAggregated records, combining their data
func MergeSessionAggregated(existing *types.DynamoDBSessionAggregated, new *types.DynamoDBSessionAggregated) *types.DynamoDBSessionAggregated {
	layout := "2006-01-02T15:04:05Z"

	// Parse times to determine which is earlier/later
	existingStart, _ := time.Parse(layout, existing.StartTime)
	newStart, _ := time.Parse(layout, new.StartTime)
	existingEnd, _ := time.Parse(layout, existing.EndTime)
	newEnd, _ := time.Parse(layout, new.EndTime)

	// Use earliest start time
	startTime := existing.StartTime
	if newStart.Before(existingStart) {
		startTime = new.StartTime
	}

	// Use latest end time
	endTime := existing.EndTime
	if newEnd.After(existingEnd) {
		endTime = new.EndTime
	}

	// Calculate duration
	start, _ := time.Parse(layout, startTime)
	end, _ := time.Parse(layout, endTime)
	durationMinutes := int(end.Sub(start).Minutes())

	// Merge event counts and resources accessed
	mergedEventCounts := MergeIntMaps(existing.EventCounts, new.EventCounts)
	mergedResourcesAccessed := MergeIntMaps(existing.ResourcesAccessed, new.ResourcesAccessed)
	mergedResourceAccesses := MergeResourceAccesses(existing.ResourceAccesses, new.ResourceAccesses)

	// Merge denied event counts and resources
	mergedDeniedEventCounts := MergeIntMaps(existing.DeniedEventCounts, new.DeniedEventCounts)
	mergedDeniedResourcesAccessed := MergeIntMaps(existing.DeniedResourcesAccessed, new.DeniedResourcesAccessed)
	mergedDeniedResourceAccesses := MergeResourceAccesses(existing.DeniedResourceAccesses, new.DeniedResourceAccesses)
	mergedDeniedEventAccesses := MergeEventAccesses(existing.DeniedEventAccesses, new.DeniedEventAccesses)

	merged := &types.DynamoDBSessionAggregated{
		CustomerID:        new.CustomerID,
		SessionID:         existing.SessionID,
		SessionType:       existing.SessionType, // Both sessions have same IAM creation time, so same type
		SessionStart:      existing.SessionStart,  // Preserve composite range key
		StartTime:         startTime,             // Pure timestamp
		EndTime:           endTime,
		DurationMinutes:   durationMinutes,
		PersonEmail:       existing.PersonEmail,
		PersonDisplayName: existing.PersonDisplayName,
		AccountID:         existing.AccountID,
		RoleARN:           existing.RoleARN,
		RoleName:          existing.RoleName,
		EventsCount:       existing.EventsCount + new.EventsCount,
		SourceIPs:         MergeUniqueStrings(existing.SourceIPs, new.SourceIPs),
		UserAgents:        MergeUniqueStrings(existing.UserAgents, new.UserAgents),
		EventCounts:       mergedEventCounts,
		ResourcesAccessed: mergedResourcesAccessed,
		ResourceAccesses:  mergedResourceAccesses,
		// Access Denied tracking
		DeniedEventCount:        existing.DeniedEventCount + new.DeniedEventCount,
		DeniedEventCounts:       mergedDeniedEventCounts,
		DeniedResourcesAccessed: mergedDeniedResourcesAccessed,
		DeniedResourceAccesses:  mergedDeniedResourceAccesses,
		DeniedEventAccesses:     mergedDeniedEventAccesses,
		// CRITICAL FIX: Calculate counts from merged unique sets, not by adding
		ServicesCount:  CountUniqueServices(mergedEventCounts),
		ResourcesCount: len(mergedResourcesAccessed),
		// Role chaining
		ChainedRoles:      MergeUniqueStrings(existing.ChainedRoles, new.ChainedRoles),
		ChainedEventCount: existing.ChainedEventCount + new.ChainedEventCount,
	}

	return merged
}

// MergeUniqueStrings merges two string slices, removing duplicates
func MergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// MergeIntMaps merges two map[string]int by adding counts
func MergeIntMaps(a, b map[string]int) map[string]int {
	result := make(map[string]int)

	for k, v := range a {
		result[k] = v
	}

	for k, v := range b {
		result[k] += v
	}

	return result
}

// CountUniqueServices counts unique services from event counts map
// Event counts are stored as "eventSource:eventName" -> count
func CountUniqueServices(eventCounts map[string]int) int {
	services := make(map[string]bool)
	for eventKey := range eventCounts {
		// Extract eventSource from "eventSource:eventName"
		parts := strings.Split(eventKey, ":")
		if len(parts) >= 1 {
			services[parts[0]] = true
		}
	}
	return len(services)
}

// MergeResourceAccesses merges two ResourceAccess slices, combining counts for duplicates
func MergeResourceAccesses(a, b []types.ResourceAccess) []types.ResourceAccess {
	// Use map to aggregate by unique combination of Resource+Service+EventName
	accessMap := make(map[string]*types.ResourceAccess)

	// Add all from first slice
	for _, ra := range a {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		accessMap[key] = &types.ResourceAccess{
			Resource:  ra.Resource,
			Service:   ra.Service,
			EventName: ra.EventName,
			Count:     ra.Count,
		}
	}

	// Merge from second slice
	for _, ra := range b {
		key := fmt.Sprintf("%s:%s:%s", ra.Service, ra.EventName, ra.Resource)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ra.Count
		} else {
			accessMap[key] = &types.ResourceAccess{
				Resource:  ra.Resource,
				Service:   ra.Service,
				EventName: ra.EventName,
				Count:     ra.Count,
			}
		}
	}

	// Convert back to slice
	result := make([]types.ResourceAccess, 0, len(accessMap))
	for _, ra := range accessMap {
		result = append(result, *ra)
	}

	return result
}

// MergeEventAccesses merges two EventAccess slices, combining counts for duplicates
func MergeEventAccesses(a, b []types.EventAccess) []types.EventAccess {
	// Use map to aggregate by unique combination of Service+EventName+PolicyARN
	accessMap := make(map[string]*types.EventAccess)

	// Add all from first slice
	for _, ea := range a {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		accessMap[key] = &types.EventAccess{
			Service:      ea.Service,
			EventName:    ea.EventName,
			Count:        ea.Count,
			PolicyARN:    ea.PolicyARN,
			PolicyType:   ea.PolicyType,
			ErrorMessage: ea.ErrorMessage,
		}
	}

	// Merge from second slice
	for _, ea := range b {
		key := fmt.Sprintf("%s:%s:%s", ea.Service, ea.EventName, ea.PolicyARN)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ea.Count
			// Keep the first error message we saw (could enhance to track multiple messages)
			if existing.ErrorMessage == "" && ea.ErrorMessage != "" {
				existing.ErrorMessage = ea.ErrorMessage
			}
		} else {
			accessMap[key] = &types.EventAccess{
				Service:      ea.Service,
				EventName:    ea.EventName,
				Count:        ea.Count,
				PolicyARN:    ea.PolicyARN,
				PolicyType:   ea.PolicyType,
				ErrorMessage: ea.ErrorMessage,
			}
		}
	}

	// Convert back to slice
	result := make([]types.EventAccess, 0, len(accessMap))
	for _, ea := range accessMap {
		result = append(result, *ea)
	}

	return result
}

// WriteChainLinkToDynamoDB writes a chain link record to DynamoDB.
// TTL is set to 12 hours from eventTime (STS max credential lifetime).
func WriteChainLinkToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, link *types.DynamoDBChainLink) error {
	item, err := attributevalue.MarshalMap(link)
	if err != nil {
		return fmt.Errorf("failed to marshal chain link: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("failed to write chain link: %w", err)
	}

	log.Printf("CHAIN_LINK_WRITE: access_key_id=%s parent_session=%s assumed_role=%s",
		link.AccessKeyID, link.ParentSessionMapKey, link.AssumedRoleARN)
	return nil
}

// BatchGetChainLinks fetches chain link records for a set of access key IDs.
// Returns a map of accessKeyID -> DynamoDBChainLink for found records.
func BatchGetChainLinks(ctx context.Context, ddbClient *dynamodb.Client, tableName string, keyIDs []string) (map[string]*types.DynamoDBChainLink, error) {
	result := make(map[string]*types.DynamoDBChainLink)
	if len(keyIDs) == 0 {
		return result, nil
	}

	// DynamoDB BatchGetItem limit is 100 keys per request
	const batchSize = 100
	for i := 0; i < len(keyIDs); i += batchSize {
		end := i + batchSize
		if end > len(keyIDs) {
			end = len(keyIDs)
		}
		batch := keyIDs[i:end]

		keys := make([]map[string]ddbtypes.AttributeValue, 0, len(batch))
		for _, keyID := range batch {
			keys = append(keys, map[string]ddbtypes.AttributeValue{
				"access_key_id": &ddbtypes.AttributeValueMemberS{Value: keyID},
			})
		}

		out, err := ddbClient.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
			RequestItems: map[string]ddbtypes.KeysAndAttributes{
				tableName: {Keys: keys},
			},
		})
		if err != nil {
			return result, fmt.Errorf("batch get chain links failed: %w", err)
		}

		for _, item := range out.Responses[tableName] {
			var link types.DynamoDBChainLink
			if err := attributevalue.UnmarshalMap(item, &link); err != nil {
				log.Printf("WARNING: failed to unmarshal chain link: %v", err)
				continue
			}
			result[link.AccessKeyID] = &link
		}
	}

	return result, nil
}

// WriteAccountToDynamoDB writes or updates an account in DynamoDB
func WriteAccountToDynamoDB(ctx context.Context, ddbClient *dynamodb.Client, tableName string, account *types.DynamoDBAccount) error {
	item, err := attributevalue.MarshalMap(account)
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}
