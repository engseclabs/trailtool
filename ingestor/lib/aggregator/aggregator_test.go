package aggregator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

// makeSessionContextWithSignIn builds a SessionContext carrying an aws:SignInSessionArn,
// as present on the MCP OAuth grant and on API calls made with the OAuth access token.
func makeSessionContextWithSignIn(creationDate, roleARN, signInSessionArn string) *types.SessionContext {
	sc := makeSessionContext(creationDate, roleARN, "")
	sc.SignInSessionArn = signInSessionArn
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

// TestTaggedAssumeRoleAttribution verifies that an AssumeRole event carrying session tags
// is attributed correctly and that the tags are propagated to the child session record.
func TestTaggedAssumeRoleAttribution(t *testing.T) {
	const (
		humanEmail     = "alice@example.com"
		parentRoleID   = "AROAALICEPARENT12345"
		parentRoleARN  = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		agentRoleARN   = "arn:aws:iam::111111111111:role/claude-code-agent"
		issuedKey      = "ASIAAGENTKEY00000001"
		creationDate   = "2026-04-20T14:00:00Z"
		accountID      = "111111111111"
	)

	// AssumeRole called by the human session with agent session tags.
	// Use a browser user agent so the parent session key uses the exact creation time
	// (not a 4-hour CLI window), ensuring the in-memory parent update path is exercised.
	agentAssumeRoleEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-20T14:30:00Z",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: parentRoleID + ":" + humanEmail,
			ARN:         "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc123/" + humanEmail,
			AccountID:   accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN, humanEmail),
		},
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		RequestParameters: map[string]interface{}{
			"roleArn":         agentRoleARN,
			"roleSessionName": "claude-code-deploy-lambda",
			"tags": []interface{}{
				map[string]interface{}{"key": "AgentName", "value": "claude-code"},
				map[string]interface{}{"key": "Task", "value": "deploy-lambda"},
				map[string]interface{}{"key": "HumanSession", "value": humanEmail},
			},
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":     issuedKey,
				"secretAccessKey": "secret",
				"sessionToken":    "token",
			},
			"assumedRoleUser": map[string]interface{}{
				"assumedRoleId": "AROAAGENTROLEID12345:claude-code-deploy-lambda",
				"arn":           "arn:aws:sts::111111111111:assumed-role/claude-code-agent/claude-code-deploy-lambda",
			},
		},
	}

	// Event generated by the agent using the issued credentials
	agentEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-20T14:31:00Z",
		EventName:   "UpdateFunctionCode20150331v2",
		EventSource: "lambda.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAAGENTROLEID12345:claude-code-deploy-lambda",
			ARN:         "arn:aws:sts::111111111111:assumed-role/claude-code-agent/claude-code-deploy-lambda",
			AccountID:   accountID,
			AccessKeyID: issuedKey,
		},
		UserAgent: "go-http-client/2.0",
	}

	sessions, err := processForTest([]types.CloudTrailRecord{agentAssumeRoleEvent, agentEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	// Find the child session keyed by the issued access key
	childKey := "cli_switch_role:" + issuedKey
	childSess, ok := sessions[childKey]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childKey, sessionKeys(sessions))
	}

	// Session type is "cli-sdk" — tags don't change the type
	if childSess.SessionType != "cli-sdk" {
		t.Errorf("child SessionType = %q, want \"cli-sdk\"", childSess.SessionType)
	}
	// Tags are propagated verbatim from the AssumeRole requestParameters
	if childSess.SessionTags["AgentName"] != "claude-code" {
		t.Errorf("child SessionTags[AgentName] = %q, want \"claude-code\"", childSess.SessionTags["AgentName"])
	}
	if childSess.SessionTags["Task"] != "deploy-lambda" {
		t.Errorf("child SessionTags[Task] = %q, want \"deploy-lambda\"", childSess.SessionTags["Task"])
	}
	if childSess.SessionTags["HumanSession"] != humanEmail {
		t.Errorf("child SessionTags[HumanSession] = %q, want %q", childSess.SessionTags["HumanSession"], humanEmail)
	}
	if childSess.ParentEmail != humanEmail {
		t.Errorf("child ParentEmail = %q, want %q", childSess.ParentEmail, humanEmail)
	}
	if childSess.EventsCount != 1 {
		t.Errorf("child EventsCount = %d, want 1", childSess.EventsCount)
	}

	// Find the parent session — browser UA means exact creation time is used as the key.
	expectedParentKey := humanEmail + ":" + parentRoleID + ":" + creationDate
	parentSess, ok := sessions[expectedParentKey]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", expectedParentKey, sessionKeys(sessions))
	}
	if parentSess.ChainedEventCount != 1 {
		t.Errorf("parent ChainedEventCount = %d, want 1", parentSess.ChainedEventCount)
	}
}

// TestMCPAgentSessionAttribution verifies the AWS MCP Server OAuth flow: a CreateOAuth2Token
// grant for the AWS MCP Server resource, followed by API calls carrying the matching
// aws:SignInSessionArn, are tagged as SessionType "agent" and correlated to the authorizing
// human session. Mirrors testdata/aws_mcp_agent_session.json.
func TestMCPAgentSessionAttribution(t *testing.T) {
	const (
		userEmail        = "testuser@example.com"
		roleID           = "AROATJHQDX737YZPEXMPL"
		roleARN          = "arn:aws:iam::111111111111:role/Admin"
		accountID        = "111111111111"
		sourceIP         = "192.0.2.2"
		humanCreation    = "2026-06-09T05:06:39Z"
		grantTime        = "2026-06-09T05:10:04Z"
		mcpResource      = "https://aws-mcp.us-west-2.api.aws/mcp"
		signInSessionArn = "arn:aws:signin:us-west-2:111111111111:session/daff060f-7871-5tg6-67yu-a07bbdabe61a"
		// Agent API calls run under a fresh session created when the token was minted.
		agentCreation = "2026-06-09T05:10:04Z"
		agentKey      = "ASIATJHQDX737MCPTOKEN"
	)

	// The human's authorizing session key (email:roleID:humanCreation).
	authorizingSessionMapKey := userEmail + ":" + roleID + ":" + humanCreation

	assumedRoleARN := "arn:aws:sts::111111111111:assumed-role/Admin/" + userEmail

	// AuthorizeOAuth2Access: browser popup, resource is the AWS MCP Server.
	authorizeEvent := types.CloudTrailRecord{
		EventTime:       "2026-06-09T05:09:00Z",
		EventName:       "AuthorizeOAuth2Access",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/149.0 Safari/537.36",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + userEmail,
			ARN:            assumedRoleARN,
			AccountID:      accountID,
			SessionContext: makeSessionContext(humanCreation, roleARN, userEmail),
		},
		RequestParameters: map[string]interface{}{
			"resource":  mcpResource,
			"client_id": "arn:aws:signin:us-west-2::external-client/dcr/609544da",
		},
	}

	// CreateOAuth2Token: mints the OAuth access token. resource is the MCP Server,
	// and additionalEventData carries the signInSessionArn correlation key.
	createTokenEvent := types.CloudTrailRecord{
		EventTime:       grantTime,
		EventName:       "CreateOAuth2Token",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "curl/8.7.1",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + userEmail,
			ARN:            assumedRoleARN,
			AccountID:      accountID,
			SessionContext: makeSessionContextWithSignIn(humanCreation, roleARN, signInSessionArn),
		},
		RequestParameters: map[string]interface{}{
			"resource":  mcpResource,
			"client_id": "arn:aws:signin:us-west-2::external-client/dcr/609544da",
		},
		AdditionalEventData: map[string]interface{}{
			"signInSessionArn": signInSessionArn,
			"grant_type":       "refresh_token",
			"success":          "true",
		},
	}

	// Agent API call: carries aws:SignInSessionArn matching the grant.
	agentEvent := types.CloudTrailRecord{
		EventTime:       "2026-06-09T05:12:31Z",
		EventName:       "ListBuckets",
		EventSource:     "s3.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-mcp-server/1.0",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + userEmail,
			ARN:            assumedRoleARN,
			AccountID:      accountID,
			AccessKeyID:    agentKey,
			SessionContext: makeSessionContextWithSignIn(agentCreation, roleARN, signInSessionArn),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{authorizeEvent, createTokenEvent, agentEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	// aws-mcp-server/1.0 is recognized as a programmatic (cli-sdk) user agent, so the agent
	// session keys off the 4-hour CLI window: agentCreation 05:10:04 → window 04:00:00Z.
	agentWindowStart := "2026-06-09T04:00:00Z"
	agentSessionKey := userEmail + ":" + roleID + ":" + agentWindowStart
	agentSess, ok := sessions[agentSessionKey]
	if !ok {
		t.Fatalf("agent session %q not found; keys: %v", agentSessionKey, sessionKeys(sessions))
	}

	if agentSess.SessionType != "agent" {
		t.Errorf("agent session SessionType = %q, want \"agent\"", agentSess.SessionType)
	}
	if agentSess.SignInSessionArn != signInSessionArn {
		t.Errorf("agent SignInSessionArn = %q, want %q", agentSess.SignInSessionArn, signInSessionArn)
	}
	if agentSess.MCPResource != mcpResource {
		t.Errorf("agent MCPResource = %q, want %q", agentSess.MCPResource, mcpResource)
	}
	if agentSess.AgentAuthorizedBySession != authorizingSessionMapKey {
		t.Errorf("agent AgentAuthorizedBySession = %q, want %q", agentSess.AgentAuthorizedBySession, authorizingSessionMapKey)
	}
	if agentSess.AgentAuthorizedByEmail != userEmail {
		t.Errorf("agent AgentAuthorizedByEmail = %q, want %q", agentSess.AgentAuthorizedByEmail, userEmail)
	}
	if agentSess.EventsCount != 1 {
		t.Errorf("agent EventsCount = %d, want 1 (CreateOAuth2Token must not inflate the count)", agentSess.EventsCount)
	}
}

// TestMCPMultipleAgentEventsCorrelate verifies that multiple API calls sharing the same
// aws:SignInSessionArn all aggregate into one agent session with the correct event count.
func TestMCPMultipleAgentEventsCorrelate(t *testing.T) {
	const (
		userEmail        = "testuser@example.com"
		roleID           = "AROATJHQDX737YZPEXMPL"
		roleARN          = "arn:aws:iam::111111111111:role/Admin"
		accountID        = "111111111111"
		sourceIP         = "192.0.2.2"
		humanCreation    = "2026-06-09T05:06:39Z"
		mcpResource      = "https://aws-mcp.us-west-2.api.aws/mcp"
		signInSessionArn = "arn:aws:signin:us-west-2:111111111111:session/multi-event-session"
		agentCreation    = "2026-06-09T05:10:04Z"
		agentKey         = "ASIATJHQDX737MCPTOKEN"
	)

	assumedRoleARN := "arn:aws:sts::111111111111:assumed-role/Admin/" + userEmail

	createTokenEvent := types.CloudTrailRecord{
		EventTime:       "2026-06-09T05:10:04Z",
		EventName:       "CreateOAuth2Token",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "curl/8.7.1",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + userEmail,
			ARN:            assumedRoleARN,
			AccountID:      accountID,
			SessionContext: makeSessionContextWithSignIn(humanCreation, roleARN, signInSessionArn),
		},
		RequestParameters: map[string]interface{}{
			"resource": mcpResource,
		},
		AdditionalEventData: map[string]interface{}{
			"signInSessionArn": signInSessionArn,
			"grant_type":       "client_credentials",
		},
	}

	newAgentEvent := func(eventTime, name, src string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:       eventTime,
			EventName:       name,
			EventSource:     src,
			SourceIPAddress: sourceIP,
			UserAgent:       "aws-mcp-server/1.0",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    roleID + ":" + userEmail,
				ARN:            assumedRoleARN,
				AccountID:      accountID,
				AccessKeyID:    agentKey,
				SessionContext: makeSessionContextWithSignIn(agentCreation, roleARN, signInSessionArn),
			},
		}
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		createTokenEvent,
		newAgentEvent("2026-06-09T05:12:31Z", "ListBuckets", "s3.amazonaws.com"),
		newAgentEvent("2026-06-09T05:12:48Z", "DescribeInstances", "ec2.amazonaws.com"),
		newAgentEvent("2026-06-09T05:13:02Z", "ListUsers", "iam.amazonaws.com"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	agentWindowStart := "2026-06-09T04:00:00Z"
	agentSessionKey := userEmail + ":" + roleID + ":" + agentWindowStart
	agentSess, ok := sessions[agentSessionKey]
	if !ok {
		t.Fatalf("agent session %q not found; keys: %v", agentSessionKey, sessionKeys(sessions))
	}
	if agentSess.SessionType != "agent" {
		t.Errorf("agent session SessionType = %q, want \"agent\"", agentSess.SessionType)
	}
	if agentSess.EventsCount != 3 {
		t.Errorf("agent EventsCount = %d, want 3", agentSess.EventsCount)
	}
}

// TestNonMCPOAuthTokenNotTaggedAgent verifies that a CreateOAuth2Token grant whose resource is
// NOT the AWS MCP Server (e.g. the aws login same-device flow) does not produce an agent session.
func TestNonMCPOAuthTokenNotTaggedAgent(t *testing.T) {
	const (
		userEmail        = "testuser@example.com"
		roleID           = "AROATJHQDX737YZPEXMPL"
		roleARN          = "arn:aws:iam::111111111111:role/Admin"
		accountID        = "111111111111"
		sourceIP         = "192.0.2.2"
		humanCreation    = "2026-06-09T05:06:39Z"
		signInSessionArn = "arn:aws:signin:us-west-2:111111111111:session/non-mcp-session"
		agentCreation    = "2026-06-09T05:10:04Z"
	)

	assumedRoleARN := "arn:aws:sts::111111111111:assumed-role/Admin/" + userEmail

	// CreateOAuth2Token WITHOUT an MCP Server resource — should not create an MCP grant.
	createTokenEvent := types.CloudTrailRecord{
		EventTime:       "2026-06-09T05:10:04Z",
		EventName:       "CreateOAuth2Token",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/command#login",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + userEmail,
			ARN:            assumedRoleARN,
			AccountID:      accountID,
			SessionContext: makeSessionContextWithSignIn(humanCreation, roleARN, signInSessionArn),
		},
		RequestParameters: map[string]interface{}{
			"client_id": "arn:aws:signin:::devtools/same-device",
		},
	}

	apiEvent := types.CloudTrailRecord{
		EventTime:       "2026-06-09T05:12:31Z",
		EventName:       "ListBuckets",
		EventSource:     "s3.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/command#s3.ls",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + userEmail,
			ARN:            assumedRoleARN,
			AccountID:      accountID,
			AccessKeyID:    "ASIATJHQDX737NONMCP0",
			SessionContext: makeSessionContextWithSignIn(agentCreation, roleARN, signInSessionArn),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{createTokenEvent, apiEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	// aws-cli user agent → 4-hour CLI window: agentCreation 05:10:04 → 04:00:00Z.
	sessionKey := userEmail + ":" + roleID + ":2026-06-09T04:00:00Z"
	sess, ok := sessions[sessionKey]
	if !ok {
		t.Fatalf("session %q not found; keys: %v", sessionKey, sessionKeys(sessions))
	}
	if sess.SessionType == "agent" {
		t.Errorf("session SessionType = %q, should not be \"agent\" for a non-MCP OAuth token", sess.SessionType)
	}
	if sess.SignInSessionArn != "" {
		t.Errorf("SignInSessionArn = %q, want empty for a non-MCP OAuth token", sess.SignInSessionArn)
	}
}

// TestMCPAgentFixture drives the testdata/aws_mcp_agent_session.json fixture end-to-end through
// the aggregator, ensuring the documented AWS MCP Server CloudTrail flow yields an agent session.
// This keeps the JSON fixture and the aggregator behaviour in sync.
func TestMCPAgentFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "aws_mcp_agent_session.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var log types.CloudTrailLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	sessions, err := processForTest(log.Records)
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	var agentSess *types.DynamoDBSessionAggregated
	for _, s := range sessions {
		if s.SessionType == "agent" {
			agentSess = s
			break
		}
	}
	if agentSess == nil {
		t.Fatalf("no agent session produced from fixture; keys: %v", sessionKeys(sessions))
	}
	if agentSess.MCPResource != "https://aws-mcp.us-west-2.api.aws/mcp" {
		t.Errorf("MCPResource = %q, want the MCP server resource", agentSess.MCPResource)
	}
	if agentSess.SignInSessionArn == "" {
		t.Error("agent session missing SignInSessionArn")
	}
	if agentSess.AgentAuthorizedByEmail != "testuser@example.com" {
		t.Errorf("AgentAuthorizedByEmail = %q, want testuser@example.com", agentSess.AgentAuthorizedByEmail)
	}
	// Both agent API calls (ListBuckets, DescribeInstances) should aggregate into this session.
	if agentSess.EventsCount != 2 {
		t.Errorf("agent EventsCount = %d, want 2 (grant/authorize events must not inflate)", agentSess.EventsCount)
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
