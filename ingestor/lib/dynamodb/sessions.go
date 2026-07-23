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
		SK:          existing.SK,  // sticky
		Sid:         existing.Sid, // sticky (derived from PK/SK, which don't change)
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
		Clients:                 MergeClients(existing.Clients, incoming.Clients),
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
		GrantedSessionRefs: MergeUniqueStrings(existing.GrantedSessionRefs, incoming.GrantedSessionRefs),

		SessionTags:   mergeSessionTags(existing.SessionTags, incoming.SessionTags),
		SessionPolicy: firstNonEmpty(existing.SessionPolicy, incoming.SessionPolicy),

		LoginGrantedBySession:    firstNonEmpty(existing.LoginGrantedBySession, incoming.LoginGrantedBySession),
		MCPResource:              firstNonEmpty(existing.MCPResource, incoming.MCPResource),
		AgentAuthorizedBySession: firstNonEmpty(existing.AgentAuthorizedBySession, incoming.AgentAuthorizedBySession),
	}
}

// MergeResourceAccesses merges two ResourceAccess slices, combining counts for
// duplicates. Used for both ResourceAccesses and DeniedResourceAccesses, so the
// merge key includes PolicyARN and the policy fields (PolicyARN, PolicyType,
// ErrorMessage) are carried through — otherwise denied entries would lose them
// when sessions merge across batches. Non-denied entries have empty policy
// fields, so this is a no-op for them.
func MergeResourceAccesses(a, b []types.ResourceAccess) []types.ResourceAccess {
	// Use map to aggregate by unique combination of Resource+Service+EventName+PolicyARN
	accessMap := make(map[string]*types.ResourceAccess)

	// Add all from first slice
	for _, ra := range a {
		key := fmt.Sprintf("%s:%s:%s:%s", ra.Service, ra.EventName, ra.Resource, ra.PolicyARN)
		accessMap[key] = &types.ResourceAccess{
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
		key := fmt.Sprintf("%s:%s:%s:%s", ra.Service, ra.EventName, ra.Resource, ra.PolicyARN)
		if existing, exists := accessMap[key]; exists {
			existing.Count += ra.Count
			// Keep the first non-empty error message we saw.
			if existing.ErrorMessage == "" && ra.ErrorMessage != "" {
				existing.ErrorMessage = ra.ErrorMessage
			}
		} else {
			accessMap[key] = &types.ResourceAccess{
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

// maxRawUASamples bounds retained raw user-agent strings per client on merge —
// must match the aggregator's cap so cross-batch merges don't grow past it.
const maxRawUASamples = 5

// MergeClients merges two []ClientAggregate additively and order-independently,
// keyed on ClientAggregate.Key. Counts sum; FirstSeen/LastSeen take the min/max;
// Commands (int maps) and Components (last-non-empty) merge per-key; raw samples
// union and stay capped. This mirrors the additive session-merge contract so a
// redelivered batch converges to the same result.
func MergeClients(a, b []types.ClientAggregate) []types.ClientAggregate {
	order := make([]string, 0, len(a)+len(b))
	byKey := make(map[string]*types.ClientAggregate)

	add := func(c types.ClientAggregate) {
		existing, ok := byKey[c.Key]
		if !ok {
			cp := c // copy; don't alias caller's backing array
			byKey[c.Key] = &cp
			order = append(order, c.Key)
			return
		}
		existing.TotalEventCount += c.TotalEventCount
		existing.DeniedEventCount += c.DeniedEventCount
		existing.ServiceDrivenEventCount += c.ServiceDrivenEventCount

		if c.FirstSeen != "" && (existing.FirstSeen == "" || c.FirstSeen < existing.FirstSeen) {
			existing.FirstSeen = c.FirstSeen
		}
		if c.LastSeen > existing.LastSeen {
			existing.LastSeen = c.LastSeen
		}

		// Identity/platform fields are part of the key or stable — fill any that
		// were empty on the first-seen side.
		existing.Version = firstNonEmpty(existing.Version, c.Version)
		existing.OS = firstNonEmpty(existing.OS, c.OS)
		existing.OSVersion = firstNonEmpty(existing.OSVersion, c.OSVersion)
		existing.Architecture = firstNonEmpty(existing.Architecture, c.Architecture)
		existing.Runtime = firstNonEmpty(existing.Runtime, c.Runtime)

		existing.Commands = MergeIntMaps(existing.Commands, c.Commands)
		existing.Components = mergeStringMaps(existing.Components, c.Components)
		existing.RawUserAgentSamples = mergeCappedSamples(existing.RawUserAgentSamples, c.RawUserAgentSamples)
	}

	for _, c := range a {
		add(c)
	}
	for _, c := range b {
		add(c)
	}

	result := make([]types.ClientAggregate, 0, len(order))
	for _, k := range order {
		result = append(result, *byKey[k])
	}
	return result
}

// mergeStringMaps merges two string maps; existing values win, incoming fills gaps.
func mergeStringMaps(existing, incoming map[string]string) map[string]string {
	if len(existing) == 0 && len(incoming) == 0 {
		return nil
	}
	out := make(map[string]string, len(existing)+len(incoming))
	for k, v := range incoming {
		if v != "" {
			out[k] = v
		}
	}
	for k, v := range existing {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// mergeCappedSamples unions two sample slices preserving order and capping length.
func mergeCappedSamples(existing, incoming []string) []string {
	out := make([]string, 0, maxRawUASamples)
	seen := make(map[string]bool)
	for _, s := range existing {
		if len(out) >= maxRawUASamples {
			return out
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range incoming {
		if len(out) >= maxRawUASamples {
			break
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
