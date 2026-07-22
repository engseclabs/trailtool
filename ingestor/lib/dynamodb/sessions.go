// Anchored sessions: deterministic keys mean cross-batch writes hit the
// same item and merge additively.
package dynamodb

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// WriteSession writes or updates an anchored session in DynamoDB. The key is
// deterministic (pk = customerId#person_key, sk = anchor#roleID), so cross-batch
// writes for the same credential hit the same item and merge additively via
// read-merge-write. Optimistic locking is not load-bearing here — a concurrent
// double-merge has the same (accepted) exposure as a redelivered partial batch.
func WriteSession(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession) error {
	getResult, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"pk": &ddbtypes.AttributeValueMemberS{Value: session.PK},
			"sk": &ddbtypes.AttributeValueMemberS{Value: session.SK},
		},
	})
	if err != nil {
		log.Printf("WARNING: Failed to get existing session: %v", err)
		// Continue with normal write if the read fails
	} else if len(getResult.Item) > 0 {
		var existing types.DynamoDBSession
		if err := attributevalue.UnmarshalMap(getResult.Item, &existing); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing session: %v", err)
		} else {
			merged := MergeSession(&existing, session)
			merged.Version = existing.Version + 1
			item, err := attributevalue.MarshalMap(merged)
			if err != nil {
				return fmt.Errorf("failed to marshal merged session: %w", err)
			}
			if _, err := ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: aws.String(tableName),
				Item:      item,
			}); err != nil {
				return fmt.Errorf("failed to write merged session: %w", err)
			}
			log.Printf("SESSION_MERGED: sk=%s events=%d (was %d, +%d)",
				merged.SK, merged.EventsCount, existing.EventsCount, session.EventsCount)
			return nil
		}
	}

	log.Printf("SESSION_CREATE: sk=%s type=%s events=%d start=%s",
		session.SK, session.SessionType, session.EventsCount, session.StartTime)
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

// MergeSession merges two session records for the same key, combining their
// data. The existing record's identity fields and sort key win (the SK is
// sticky for win# sessions); Version is the caller's concern.
func MergeSession(existing *types.DynamoDBSession, incoming *types.DynamoDBSession) *types.DynamoDBSession {
	// RFC3339 UTC timestamps compare lexicographically.
	startTime := existing.StartTime
	if incoming.StartTime != "" && (startTime == "" || incoming.StartTime < startTime) {
		startTime = incoming.StartTime
	}
	endTime := existing.EndTime
	if incoming.EndTime > endTime {
		endTime = incoming.EndTime
	}
	durationMinutes := 0
	if start, err := time.Parse(time.RFC3339, startTime); err == nil {
		if end, err := time.Parse(time.RFC3339, endTime); err == nil {
			durationMinutes = int(end.Sub(start).Minutes())
		}
	}

	mergedEventCounts := MergeIntMaps(existing.EventCounts, incoming.EventCounts)
	mergedResourcesAccessed := MergeIntMaps(existing.ResourcesAccessed, incoming.ResourcesAccessed)

	// Session type specificity: "agent" (MCP OAuth traffic) is the most specific,
	// then "login" (aws login). Prefer the more specific type if either side
	// carries it; otherwise keep the existing type.
	sessionType := existing.SessionType
	if incoming.SessionType == "login" || existing.SessionType == "login" {
		sessionType = "login"
	}
	if incoming.SessionType == "agent" || existing.SessionType == "agent" {
		sessionType = "agent"
	}

	return &types.DynamoDBSession{
		PK:          existing.PK,
		SK:          existing.SK, // sticky
		CustomerID:  existing.CustomerID,
		PersonKey:   existing.PersonKey,
		Anchor:      firstNonEmpty(existing.Anchor, incoming.Anchor),
		SessionType: sessionType,
		RoleARN:     firstNonEmpty(existing.RoleARN, incoming.RoleARN),
		RoleID:      firstNonEmpty(existing.RoleID, incoming.RoleID),
		RoleName:    firstNonEmpty(existing.RoleName, incoming.RoleName),
		AccountID:   firstNonEmpty(existing.AccountID, incoming.AccountID),
		RoleKey:     firstNonEmpty(existing.RoleKey, incoming.RoleKey),
		AccountKey:  firstNonEmpty(existing.AccountKey, incoming.AccountKey),

		StartTime:       startTime,
		EndTime:         endTime,
		DurationMinutes: durationMinutes,
		Version:         existing.Version,

		EventsCount:             existing.EventsCount + incoming.EventsCount,
		ServiceDrivenEventCount: existing.ServiceDrivenEventCount + incoming.ServiceDrivenEventCount,
		SourceIPs:               MergeUniqueStrings(existing.SourceIPs, incoming.SourceIPs),
		UserAgents:              MergeUniqueStrings(existing.UserAgents, incoming.UserAgents),
		EventCounts:             mergedEventCounts,
		ResourcesAccessed:       mergedResourcesAccessed,
		ResourceAccesses:        MergeResourceAccesses(existing.ResourceAccesses, incoming.ResourceAccesses),
		ServicesCount:           CountUniqueServices(mergedEventCounts),
		ResourcesCount:          len(mergedResourcesAccessed),

		DeniedEventCount:        existing.DeniedEventCount + incoming.DeniedEventCount,
		DeniedEventCounts:       MergeIntMaps(existing.DeniedEventCounts, incoming.DeniedEventCounts),
		DeniedResourcesAccessed: MergeIntMaps(existing.DeniedResourcesAccessed, incoming.DeniedResourcesAccessed),
		DeniedResourceAccesses:  MergeResourceAccesses(existing.DeniedResourceAccesses, incoming.DeniedResourceAccesses),
		DeniedEventAccesses:     MergeEventAccesses(existing.DeniedEventAccesses, incoming.DeniedEventAccesses),

		ClickOpsEventCount:  existing.ClickOpsEventCount + incoming.ClickOpsEventCount,
		ClickOpsEventCounts: MergeIntMaps(existing.ClickOpsEventCounts, incoming.ClickOpsEventCounts),

		SignInSessionArn: firstNonEmpty(existing.SignInSessionArn, incoming.SignInSessionArn),

		AssumedFromSession: firstNonEmpty(existing.AssumedFromSession, incoming.AssumedFromSession),
		AssumedFromRoleARN: firstNonEmpty(existing.AssumedFromRoleARN, incoming.AssumedFromRoleARN),
		ChainedSessionRefs: MergeUniqueStrings(existing.ChainedSessionRefs, incoming.ChainedSessionRefs),
		ChainedRoles:       MergeUniqueStrings(existing.ChainedRoles, incoming.ChainedRoles),
		ChainedEventCount:  existing.ChainedEventCount + incoming.ChainedEventCount,

		SessionTags:   mergeSessionTags(existing.SessionTags, incoming.SessionTags),
		SessionPolicy: firstNonEmpty(existing.SessionPolicy, incoming.SessionPolicy),

		LoginGrantedBySession:    firstNonEmpty(existing.LoginGrantedBySession, incoming.LoginGrantedBySession),
		MCPResource:              firstNonEmpty(existing.MCPResource, incoming.MCPResource),
		AgentAuthorizedBySession: firstNonEmpty(existing.AgentAuthorizedBySession, incoming.AgentAuthorizedBySession),
	}
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
