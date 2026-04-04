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

	// Find the parent session — it's keyed by creationDate (web-console from Chrome UA)
	expectedKey := parentEmail + ":" + parentRoleID + ":" + creationDate

	sess, ok := sessions[expectedKey]
	if !ok {
		t.Fatalf("parent session %q not found in sessions map; keys: %v", expectedKey, sessionKeys(sessions))
	}

	if sess.ChainedEventCount != 2 {
		t.Errorf("ChainedEventCount = %d, want 2", sess.ChainedEventCount)
	}

	if len(sess.ChainedRoles) != 1 || sess.ChainedRoles[0] != assumedRoleARN {
		t.Errorf("ChainedRoles = %v, want [%s]", sess.ChainedRoles, assumedRoleARN)
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
