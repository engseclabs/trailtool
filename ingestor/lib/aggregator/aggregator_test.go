package aggregator

import (
	"context"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// makeSessionContext builds a SessionContext for a human Identity Center session.
func makeSessionContext(creationDate, roleARN, email string) *types.SessionContext {
	sc := &types.SessionContext{}
	sc.Attributes.CreationDate = creationDate
	sc.SessionIssuer.ARN = roleARN
	sc.SessionIssuer.Type = "Role"
	return sc
}

// TestTwoPassChainAttributionCounts verifies the chained event count and roles
// are accumulated on the parent session, using an exported helper so we can
// inspect the in-memory sessions map.
func TestTwoPassChainAttributionCounts(t *testing.T) {
	const (
		parentEmail    = "bob@example.com"
		parentRoleID   = "AROABOBEXAMPLE12345"
		parentRoleARN  = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Viewer_def456"
		assumedRoleARN = "arn:aws:iam::333333333333:role/ReadOnlyRole"
		issuedKey      = "ASIABOBKEY1234567890"
		creationDate   = "2024-02-01T08:00:00Z"
		accountID      = "111111111111"
	)

	assumeRoleEvent := types.CloudTrailRecord{
		EventTime:   "2024-02-01T08:05:00Z",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: parentRoleID + ":" + parentEmail,
			ARN:         "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Viewer_def456/" + parentEmail,
			AccountID:   accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN, parentEmail),
		},
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		RequestParameters: map[string]interface{}{
			"roleArn":         assumedRoleARN,
			"roleSessionName": "read-session",
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":     issuedKey,
				"secretAccessKey": "secret",
				"sessionToken":    "token",
			},
		},
	}

	// Two chained events — both should land on the parent session
	chainedEvent1 := types.CloudTrailRecord{
		EventTime:   "2024-02-01T08:10:00Z",
		EventName:   "ListBuckets",
		EventSource: "s3.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAREADONLY:read-session",
			ARN:         "arn:aws:sts::333333333333:assumed-role/ReadOnlyRole/read-session",
			AccountID:   "333333333333",
			AccessKeyID: issuedKey,
		},
		UserAgent: "aws-cli/2.15.0",
	}
	chainedEvent2 := types.CloudTrailRecord{
		EventTime:   "2024-02-01T08:11:00Z",
		EventName:   "DescribeInstances",
		EventSource: "ec2.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAREADONLY:read-session",
			ARN:         "arn:aws:sts::333333333333:assumed-role/ReadOnlyRole/read-session",
			AccountID:   "333333333333",
			AccessKeyID: issuedKey,
		},
		UserAgent: "aws-cli/2.15.0",
	}

	// Use the testable helper that returns the sessions map
	sessions, err := processForTest([]types.CloudTrailRecord{assumeRoleEvent, chainedEvent1, chainedEvent2})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	// Find the parent session — keyed by creationDate (web-console from Chrome UA)
	expectedParentKey := parentEmail + ":" + parentRoleID + ":" + creationDate
	parentSess, ok := sessions[expectedParentKey]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", expectedParentKey, sessionKeys(sessions))
	}

	// Parent should have summary counts but NOT the chained events' own events
	if parentSess.ChainedEventCount != 2 {
		t.Errorf("parent ChainedEventCount = %d, want 2", parentSess.ChainedEventCount)
	}
	if len(parentSess.ChainedRoles) != 1 || parentSess.ChainedRoles[0] != assumedRoleARN {
		t.Errorf("parent ChainedRoles = %v, want [%s]", parentSess.ChainedRoles, assumedRoleARN)
	}
	// Parent should know the child session key (full session_start: "startTime#sessionID")
	expectedChildSessionStart := "2024-02-01T08:10:00Z#" + issuedKey
	if len(parentSess.ChainedSessionKeys) != 1 || parentSess.ChainedSessionKeys[0] != expectedChildSessionStart {
		t.Errorf("parent ChainedSessionKeys = %v, want [%s]", parentSess.ChainedSessionKeys, expectedChildSessionStart)
	}

	// Find the child session — keyed by the issued access key ID (stable across all events)
	childSessionID := issuedKey
	childSess, ok := sessions[childSessionID]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childSessionID, sessionKeys(sessions))
	}

	// Child session should have its own events
	if childSess.EventsCount != 2 {
		t.Errorf("child EventsCount = %d, want 2", childSess.EventsCount)
	}
	// Child links back to parent
	if childSess.ParentSessionKey != expectedParentKey {
		t.Errorf("child ParentSessionKey = %q, want %q", childSess.ParentSessionKey, expectedParentKey)
	}
	if childSess.ParentEmail != parentEmail {
		t.Errorf("child ParentEmail = %q, want %q", childSess.ParentEmail, parentEmail)
	}
	// Child session carries the assumed role identity
	if childSess.RoleARN != assumedRoleARN {
		t.Errorf("child RoleARN = %q, want %q", childSess.RoleARN, assumedRoleARN)
	}
}

// TestConsoleRoleSwitchChaining verifies that a console switch-role (where the chained
// session events still carry the user's email in PrincipalID) is attributed correctly.
func TestConsoleRoleSwitchChaining(t *testing.T) {
	const (
		parentEmail      = "alice@example.com"
		parentRoleID     = "AROAALICEPARENT12345"
		parentRoleARN    = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		assumedRoleARN   = "arn:aws:iam::222222222222:role/RoleChaining1"
		assumedRoleID    = "AROACHAINING000001"
		issuedKey        = "ASIACONSOLEKEY12345"
		creationDate     = "2024-03-01T10:00:00Z"
		accountID        = "111111111111"
	)

	assumeRoleEvent := types.CloudTrailRecord{
		EventTime:   "2024-03-01T10:05:00Z",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: parentRoleID + ":" + parentEmail,
			ARN:         "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc123/" + parentEmail,
			AccountID:   accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN, parentEmail),
		},
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		RequestParameters: map[string]interface{}{
			"roleArn":         assumedRoleARN,
			"roleSessionName": parentEmail,
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":     issuedKey,
				"secretAccessKey": "secret",
				"sessionToken":    "token",
			},
		},
	}

	// Console switch-role events carry the email in PrincipalID
	chainedEvent := types.CloudTrailRecord{
		EventTime:   "2024-03-01T10:10:00Z",
		EventName:   "ListBuckets",
		EventSource: "s3.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: assumedRoleID + ":" + parentEmail,
			ARN:         "arn:aws:sts::222222222222:assumed-role/RoleChaining1/" + parentEmail,
			AccountID:   "222222222222",
			AccessKeyID: issuedKey,
			SessionContext: makeSessionContext(creationDate, assumedRoleARN, parentEmail),
		},
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
	}

	sessions, err := processForTest([]types.CloudTrailRecord{assumeRoleEvent, chainedEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	expectedParentKey := parentEmail + ":" + parentRoleID + ":" + creationDate
	parentSess, ok := sessions[expectedParentKey]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", expectedParentKey, sessionKeys(sessions))
	}

	if parentSess.ChainedEventCount != 1 {
		t.Errorf("parent ChainedEventCount = %d, want 1", parentSess.ChainedEventCount)
	}
	if len(parentSess.ChainedRoles) != 1 || parentSess.ChainedRoles[0] != assumedRoleARN {
		t.Errorf("parent ChainedRoles = %v, want [%s]", parentSess.ChainedRoles, assumedRoleARN)
	}

	// For console switch-role, the child session now uses the natural email:roleID:creationTime key
	// (not the old chained:accessKey format).
	childSessionMapKey := parentEmail + ":" + assumedRoleID + ":" + creationDate
	childSess, ok := sessions[childSessionMapKey]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childSessionMapKey, sessionKeys(sessions))
	}
	if childSess.EventsCount != 1 {
		t.Errorf("child EventsCount = %d, want 1", childSess.EventsCount)
	}
	if childSess.ParentSessionKey != expectedParentKey {
		t.Errorf("child ParentSessionKey = %q, want %q", childSess.ParentSessionKey, expectedParentKey)
	}
	// Verify the old chained:accessKey format is NOT created
	oldChainedKey := "chained:" + issuedKey
	if _, exists := sessions[oldChainedKey]; exists {
		t.Errorf("should not create old-style chained session %q", oldChainedKey)
	}
}

// processForTest runs Process and returns the in-memory sessions map for inspection.
// It uses an empty Tables config to skip all DynamoDB I/O.
func processForTest(events []types.CloudTrailRecord) (map[string]*types.DynamoDBSessionAggregated, error) {
	return processInternal(context.Background(), nil, Config{
		Tables:    Tables{},
		Namespace: "test",
	}, events)
}

func sessionKeys(m map[string]*types.DynamoDBSessionAggregated) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
