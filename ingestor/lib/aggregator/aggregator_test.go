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
	childSessionMapKey := "cli_switch_role:" + issuedKey
	expectedChildSessionStart := "2024-02-01T08:10:00Z#" + childSessionMapKey
	if len(parentSess.ChainedSessionKeys) != 1 || parentSess.ChainedSessionKeys[0] != expectedChildSessionStart {
		t.Errorf("parent ChainedSessionKeys = %v, want [%s]", parentSess.ChainedSessionKeys, expectedChildSessionStart)
	}

	// Find the child session — keyed by "cli_switch_role:accessKeyID"
	childSess, ok := sessions[childSessionMapKey]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childSessionMapKey, sessionKeys(sessions))
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

// TestAwsLoginSessionDetection verifies that a CreateOAuth2Token event from signin.amazonaws.com
// causes the subsequent AssumedRole session (same roleARN + sourceIP, creationDate within ±60s)
// to be tagged as SessionType="login" with LoginGrantedBySessionKey/Email set.
//
// This exercises the aws login (PKCE OAuth2) flow where credentials are vended directly inside
// the CreateOAuth2Token response — no GetRoleCredentials event fires afterward.
func TestAwsLoginSessionDetection(t *testing.T) {
	const (
		parentEmail      = "alex@engseclabs.com"
		parentRoleID     = "AROAUB266OVZCWROZTVQR"
		parentRoleARN    = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
		sourceIP         = "192.0.2.1"
		accountID        = "278835131762"
		// The aws login browser popup: existing session authorizes the OAuth2 request.
		authorizeTime    = "2026-04-16T17:43:25Z"
		// The CLI completes the PKCE code exchange and receives STS credentials.
		createTokenTime  = "2026-04-16T17:43:26Z"
		// Authorizing session creation time (the human's existing SSO session).
		parentCreation   = "2026-04-16T17:43:08Z"
		// Child session (the agent) is created at the same moment credentials are vended.
		agentCreation    = "2026-04-16T17:43:08Z"
	)

	parentSessionMapKey := parentEmail + ":" + parentRoleID + ":" + parentCreation

	// AuthorizeOAuth2Access: browser popup — userAgent is Safari, userIdentity is existing AssumedRole.
	authorizeEvent := types.CloudTrailRecord{
		EventTime:       authorizeTime,
		EventName:       "AuthorizeOAuth2Access",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + parentEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(parentCreation, parentRoleARN, parentEmail),
		},
	}

	// CreateOAuth2Token: CLI completes PKCE exchange — userAgent is aws-cli with md/command#login.
	// STS credentials are vended inside this response (no GetRoleCredentials fires later).
	createTokenEvent := types.CloudTrailRecord{
		EventTime:       createTokenTime,
		EventName:       "CreateOAuth2Token",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 os/macos#25.2.0 md/arch#arm64 lang/python#3.14.4 md/pyimpl#CPython m/Z,E,b,AA cfg/retry-mode#standard md/installer#exe sid/ceb415febc00 md/prompt#off md/command#login",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + parentEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(parentCreation, parentRoleARN, parentEmail),
		},
	}

	// Agent API call: same role, same sourceIP, creationDate == agentCreation (within 60s of createTokenTime).
	agentRoleID := parentRoleID // same role — aws login vends creds for the same role
	agentEvent := types.CloudTrailRecord{
		EventTime:       "2026-04-16T17:51:59Z",
		EventName:       "ListUsers",
		EventSource:     "iam.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 os/macos#25.2.0 md/arch#arm64 lang/python#3.14.4 md/pyimpl#CPython m/AC,AD,Z,E,C,b cfg/retry-mode#standard md/installer#exe sid/0ce22194f7b7 md/prompt#off md/command#iam.list-users",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: agentRoleID + ":" + parentEmail,
			ARN:         "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + parentEmail,
			AccountID:   accountID,
			AccessKeyID: "ASIAUB266OVZDVEW755K",
			SessionContext: makeSessionContext(agentCreation, parentRoleARN, parentEmail),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{authorizeEvent, createTokenEvent, agentEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	// The agent session key: same email:roleID but uses 4-hour CLI window (agentCreation is 17:43:08 → window 16:00:00)
	// Actually: same role, CLI user agent → GenerateSessionKey uses 4-hour window.
	// agentCreation 17:43:08 → window start 16:00:00Z
	agentWindowStart := "2026-04-16T16:00:00Z"
	agentSessionKey := parentEmail + ":" + agentRoleID + ":" + agentWindowStart

	agentSess, ok := sessions[agentSessionKey]
	if !ok {
		t.Fatalf("agent session %q not found; keys: %v", agentSessionKey, sessionKeys(sessions))
	}

	if agentSess.SessionType != "login" {
		t.Errorf("agent session SessionType = %q, want \"login\"", agentSess.SessionType)
	}
	if agentSess.LoginGrantedBySessionKey != parentSessionMapKey {
		t.Errorf("agent LoginGrantedBySessionKey = %q, want %q", agentSess.LoginGrantedBySessionKey, parentSessionMapKey)
	}
	if agentSess.LoginGrantedByEmail != parentEmail {
		t.Errorf("agent LoginGrantedByEmail = %q, want %q", agentSess.LoginGrantedByEmail, parentEmail)
	}
	if agentSess.EventsCount != 1 {
		t.Errorf("agent EventsCount = %d, want 1", agentSess.EventsCount)
	}
}

// TestAwsLoginOutsideWindow verifies that a CreateOAuth2Token event does NOT tag a session
// whose creationDate is more than 60 seconds away.
func TestAwsLoginOutsideWindow(t *testing.T) {
	const (
		parentEmail     = "alex@engseclabs.com"
		parentRoleID    = "AROAUB266OVZCWROZTVQR"
		parentRoleARN   = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
		sourceIP        = "192.0.2.1"
		accountID       = "278835131762"
		parentCreation  = "2026-04-16T17:43:08Z"
		createTokenTime = "2026-04-16T17:43:26Z"
		// Agent session created 5 minutes after the token — outside the ±60s window.
		agentCreation = "2026-04-16T17:48:30Z"
	)

	createTokenEvent := types.CloudTrailRecord{
		EventTime:       createTokenTime,
		EventName:       "CreateOAuth2Token",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 md/command#login",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + parentEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(parentCreation, parentRoleARN, parentEmail),
		},
	}

	agentEvent := types.CloudTrailRecord{
		EventTime:       "2026-04-16T17:51:00Z",
		EventName:       "ListUsers",
		EventSource:     "iam.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 md/command#iam.list-users",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + parentEmail,
			AccountID:      accountID,
			AccessKeyID:    "ASIAUB266OVZDVEW755K",
			SessionContext: makeSessionContext(agentCreation, parentRoleARN, parentEmail),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{createTokenEvent, agentEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	// agentCreation 17:48:30 → 4-hour window 16:00:00Z — same window as the in-window test
	agentWindowStart := "2026-04-16T16:00:00Z"
	agentSessionKey := parentEmail + ":" + parentRoleID + ":" + agentWindowStart

	agentSess, ok := sessions[agentSessionKey]
	if !ok {
		t.Fatalf("agent session %q not found; keys: %v", agentSessionKey, sessionKeys(sessions))
	}

	if agentSess.SessionType == "login" {
		t.Errorf("agent session SessionType = %q, should not be \"login\" (creationDate outside ±60s window)", agentSess.SessionType)
	}
	if agentSess.LoginGrantedBySessionKey != "" {
		t.Errorf("agent LoginGrantedBySessionKey = %q, want empty", agentSess.LoginGrantedBySessionKey)
	}
}

// TestSsoLoginGetRoleCredentialsNotTagged verifies that a regular aws sso login session
// (which uses GetRoleCredentials, not CreateOAuth2Token) is NOT tagged as "login" type.
// The sso_login_session.json fixture represents this flow.
func TestSsoLoginGetRoleCredentialsNotTagged(t *testing.T) {
	const (
		userEmail      = "alex@engseclabs.com"
		userRoleID     = "AROAUB266OVZNNBCMBRFT"
		userRoleARN    = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_SandboxPowerUser_50d858085657c5c1"
		sourceIP       = "192.0.2.1"
		accountID      = "278835131762"
		creationDate   = "2026-04-16T17:39:11Z"
	)

	// GetRoleCredentials fires from sso.amazonaws.com with IdentityCenterUser identity —
	// this is NOT a CreateOAuth2Token, so no login pre-pass entry is created.
	getRoleCredsEvent := types.CloudTrailRecord{
		EventTime:       creationDate,
		EventName:       "GetRoleCredentials",
		EventSource:     "sso.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 md/command#sts.get-caller-identity",
		UserIdentity: types.UserIdentity{
			Type:      "IdentityCenterUser",
			AccountID: "843363563907",
		},
	}

	apiEvent := types.CloudTrailRecord{
		EventTime:       "2026-04-16T17:39:17Z",
		EventName:       "ListBuckets",
		EventSource:     "s3.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 md/command#s3.ls",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    userRoleID + ":" + userEmail,
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_SandboxPowerUser_50d858085657c5c1/" + userEmail,
			AccountID:      accountID,
			AccessKeyID:    "ASIAUB266OVZEKHQQZXJ",
			SessionContext: makeSessionContext(creationDate, userRoleARN, userEmail),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{getRoleCredsEvent, apiEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	// Session should use 4-hour CLI window: creationDate 17:39:11 → window 16:00:00Z
	agentWindowStart := "2026-04-16T16:00:00Z"
	sessionKey := userEmail + ":" + userRoleID + ":" + agentWindowStart

	sess, ok := sessions[sessionKey]
	if !ok {
		t.Fatalf("session %q not found; keys: %v", sessionKey, sessionKeys(sessions))
	}

	if sess.SessionType == "login" {
		t.Errorf("session SessionType = %q, should not be \"login\" for aws sso login flow", sess.SessionType)
	}
	if sess.LoginGrantedBySessionKey != "" {
		t.Errorf("LoginGrantedBySessionKey = %q, want empty for aws sso login flow", sess.LoginGrantedBySessionKey)
	}
	if sess.EventsCount != 1 {
		t.Errorf("EventsCount = %d, want 1", sess.EventsCount)
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
