package aggregator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// makeSessionContext builds a SessionContext for a role session.
func makeSessionContext(creationDate, roleARN string) *types.SessionContext {
	sc := &types.SessionContext{}
	sc.Attributes.CreationDate = creationDate
	sc.SessionIssuer.ARN = roleARN
	sc.SessionIssuer.Type = "Role"
	return sc
}

// makeSessionContextWithSignIn builds a SessionContext carrying an aws:SignInSessionArn,
// as present on the MCP OAuth grant and on API calls made with the OAuth access token.
func makeSessionContextWithSignIn(creationDate, roleARN, signInSessionArn string) *types.SessionContext {
	sc := makeSessionContext(creationDate, roleARN)
	sc.SignInSessionArn = signInSessionArn
	return sc
}

// ref builds the expected session ref for an anchored session.
func ref(personKey, anchor, roleID string) string {
	return identity.SessionRef(personKey, identity.SessionSK(anchor, roleID))
}

// processForTest runs the aggregation and returns the in-memory sessions map
// (keyed by session ref "person_key|sk"). Empty Tables skip all DynamoDB I/O.
func processForTest(events []types.CloudTrailRecord) (map[string]*types.DynamoDBSession, error) {
	return processInternal(context.Background(), nil, Config{
		Tables:    Tables{},
		Namespace: "test",
	}, events)
}

func sessionKeys(m map[string]*types.DynamoDBSession) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestChainAttributionCounts verifies programmatic role chaining: the child
// credential is one key# session under the person's own partition with
// assumed_from_session set, and the parent session accumulates chained counters.
func TestChainAttributionCounts(t *testing.T) {
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
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Viewer_def456/" + parentEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
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

	newChainedEvent := func(eventTime, name, src string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: src,
			UserIdentity: types.UserIdentity{
				Type:        "AssumedRole",
				PrincipalID: "AROAREADONLY:read-session",
				ARN:         "arn:aws:sts::333333333333:assumed-role/ReadOnlyRole/read-session",
				AccountID:   "333333333333",
				AccessKeyID: issuedKey,
			},
			UserAgent: "aws-cli/2.15.0",
		}
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		assumeRoleEvent,
		newChainedEvent("2024-02-01T08:10:00Z", "ListBuckets", "s3.amazonaws.com"),
		newChainedEvent("2024-02-01T08:11:00Z", "DescribeInstances", "ec2.amazonaws.com"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := "email#" + parentEmail
	parentAnchor := "web#" + parentRoleID + "#" + creationDate
	parentRef := ref(personKey, parentAnchor, parentRoleID)
	childRef := ref(personKey, "key#"+issuedKey, "AROAREADONLY")

	parentSess, ok := sessions[parentRef]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", parentRef, sessionKeys(sessions))
	}
	if parentSess.ChainedEventCount != 2 {
		t.Errorf("parent ChainedEventCount = %d, want 2", parentSess.ChainedEventCount)
	}
	if len(parentSess.ChainedRoles) != 1 || parentSess.ChainedRoles[0] != assumedRoleARN {
		t.Errorf("parent ChainedRoles = %v, want [%s]", parentSess.ChainedRoles, assumedRoleARN)
	}
	if len(parentSess.ChainedSessionRefs) != 1 || parentSess.ChainedSessionRefs[0] != childRef {
		t.Errorf("parent ChainedSessionRefs = %v, want [%s]", parentSess.ChainedSessionRefs, childRef)
	}

	childSess, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if childSess.EventsCount != 2 {
		t.Errorf("child EventsCount = %d, want 2", childSess.EventsCount)
	}
	if childSess.PersonKey != personKey {
		t.Errorf("child PersonKey = %q, want %q (chained session lives under the person)", childSess.PersonKey, personKey)
	}
	if childSess.AssumedFromSession != parentRef {
		t.Errorf("child AssumedFromSession = %q, want %q", childSess.AssumedFromSession, parentRef)
	}
	if childSess.AssumedFromRoleARN != parentRoleARN {
		t.Errorf("child AssumedFromRoleARN = %q, want %q", childSess.AssumedFromRoleARN, parentRoleARN)
	}
	if childSess.RoleARN != assumedRoleARN {
		t.Errorf("child RoleARN = %q, want %q", childSess.RoleARN, assumedRoleARN)
	}
	if childSess.SessionType != SessionTypeCLI {
		t.Errorf("child SessionType = %q, want %q", childSess.SessionType, SessionTypeCLI)
	}
}

// TestConsoleRoleSwitchChaining verifies §8.1(13): the console's AssumeRole vends
// a child *console* session — fresh access key per request but one creationDate
// (== the AssumeRole event time). The cascade anchors it web#, and the
// console-variant chain link attributes it to the person with
// assumed_from_session pointing at the parent.
func TestConsoleRoleSwitchChaining(t *testing.T) {
	const (
		parentEmail    = "alice@example.com"
		parentRoleID   = "AROAALICEPARENT12345"
		parentRoleARN  = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		assumedRoleARN = "arn:aws:iam::222222222222:role/RoleChaining1"
		assumedRoleID  = "AROACHAINING000001"
		issuedKey      = "ASIACONSOLEKEY12345"
		creationDate   = "2024-03-01T10:00:00Z"
		switchTime     = "2024-03-01T10:05:00Z" // AssumeRole event time == child creationDate
		accountID      = "111111111111"
		browserUA      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
	)

	assumeRoleEvent := types.CloudTrailRecord{
		EventTime:   switchTime,
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc123/" + parentEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
		},
		UserAgent: browserUA,
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
			"assumedRoleUser": map[string]interface{}{
				"assumedRoleId": assumedRoleID + ":" + parentEmail,
				"arn":           "arn:aws:sts::222222222222:assumed-role/RoleChaining1/" + parentEmail,
			},
		},
	}

	// Child console events: a fresh access key per request, one creationDate.
	newChildEvent := func(eventTime, name, src, requestKey string) types.CloudTrailRecord {
		e := types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: src,
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    assumedRoleID + ":" + parentEmail,
				ARN:            "arn:aws:sts::222222222222:assumed-role/RoleChaining1/" + parentEmail,
				AccountID:      "222222222222",
				AccessKeyID:    requestKey,
				SessionContext: makeSessionContext(switchTime, assumedRoleARN),
			},
			UserAgent: browserUA,
		}
		e.UserIdentity.SessionContext.Attributes.SessionCredentialFromConsole = "true"
		return e
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		assumeRoleEvent,
		newChildEvent("2024-03-01T10:10:00Z", "ListBuckets", "s3.amazonaws.com", "ASIACHILDREQ1"),
		newChildEvent("2024-03-01T10:11:00Z", "DescribeInstances", "ec2.amazonaws.com", "ASIACHILDREQ2"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := "email#" + parentEmail
	parentRef := ref(personKey, "web#"+parentRoleID+"#"+creationDate, parentRoleID)
	childRef := ref(personKey, "web#"+assumedRoleID+"#"+switchTime, assumedRoleID)

	parentSess, ok := sessions[parentRef]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", parentRef, sessionKeys(sessions))
	}
	if parentSess.ChainedEventCount != 2 {
		t.Errorf("parent ChainedEventCount = %d, want 2", parentSess.ChainedEventCount)
	}
	if len(parentSess.ChainedRoles) != 1 || parentSess.ChainedRoles[0] != assumedRoleARN {
		t.Errorf("parent ChainedRoles = %v, want [%s]", parentSess.ChainedRoles, assumedRoleARN)
	}

	childSess, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if childSess.EventsCount != 2 {
		t.Errorf("child EventsCount = %d, want 2 (per-request keys must not split the child)", childSess.EventsCount)
	}
	if childSess.SessionType != SessionTypeWeb {
		t.Errorf("child SessionType = %q, want %q", childSess.SessionType, SessionTypeWeb)
	}
	if childSess.AssumedFromSession != parentRef {
		t.Errorf("child AssumedFromSession = %q, want %q", childSess.AssumedFromSession, parentRef)
	}
	if childSess.RoleARN != assumedRoleARN {
		t.Errorf("child RoleARN = %q, want %q", childSess.RoleARN, assumedRoleARN)
	}
}

// TestAwsLoginSessionDetection verifies the aws login (PKCE OAuth2) flow: the
// CreateOAuth2Token grant registers a login# link, and the vended credential's
// session (key# anchor, same roleID+creationDate) is typed "login" with
// login_granted_by_session pointing at the authorizing session. The authorizing
// web session itself stays typed "web".
func TestAwsLoginSessionDetection(t *testing.T) {
	const (
		parentEmail    = "alex@engseclabs.com"
		roleID         = "AROAUB266OVZCWROZTVQR"
		roleARN        = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
		sourceIP       = "192.0.2.1"
		accountID      = "278835131762"
		parentCreation = "2026-04-16T17:43:08Z"
		vendedKey      = "ASIAUB266OVZDVEW755K"
	)
	stsARN := "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + parentEmail

	authorizeEvent := types.CloudTrailRecord{
		EventTime:       "2026-04-16T17:43:25Z",
		EventName:       "AuthorizeOAuth2Access",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + parentEmail,
			ARN:            stsARN,
			AccountID:      accountID,
			SessionContext: makeSessionContext(parentCreation, roleARN),
		},
	}

	createTokenEvent := types.CloudTrailRecord{
		EventTime:       "2026-04-16T17:43:26Z",
		EventName:       "CreateOAuth2Token",
		EventSource:     "signin.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/command#login",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + parentEmail,
			ARN:            stsARN,
			AccountID:      accountID,
			SessionContext: makeSessionContext(parentCreation, roleARN),
		},
	}

	// Vended-credential API call: same role, creationDate == the grant's.
	agentEvent := types.CloudTrailRecord{
		EventTime:       "2026-04-16T17:51:59Z",
		EventName:       "ListUsers",
		EventSource:     "iam.amazonaws.com",
		SourceIPAddress: sourceIP,
		UserAgent:       "aws-cli/2.34.30 md/command#iam.list-users",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + parentEmail,
			ARN:            stsARN,
			AccountID:      accountID,
			AccessKeyID:    vendedKey,
			SessionContext: makeSessionContext(parentCreation, roleARN),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{authorizeEvent, createTokenEvent, agentEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := "email#" + parentEmail
	parentRef := ref(personKey, "web#"+roleID+"#"+parentCreation, roleID)
	vendedRef := ref(personKey, "key#"+vendedKey, roleID)

	parentSess, ok := sessions[parentRef]
	if !ok {
		t.Fatalf("authorizing session %q not found; keys: %v", parentRef, sessionKeys(sessions))
	}
	if parentSess.SessionType != SessionTypeWeb {
		t.Errorf("authorizing session SessionType = %q, want %q (web# beats login# link)", parentSess.SessionType, SessionTypeWeb)
	}
	if parentSess.EventsCount != 1 {
		t.Errorf("authorizing session EventsCount = %d, want 1 (grant must not inflate)", parentSess.EventsCount)
	}

	vendedSess, ok := sessions[vendedRef]
	if !ok {
		t.Fatalf("vended session %q not found; keys: %v", vendedRef, sessionKeys(sessions))
	}
	if vendedSess.SessionType != SessionTypeLogin {
		t.Errorf("vended session SessionType = %q, want %q", vendedSess.SessionType, SessionTypeLogin)
	}
	if vendedSess.LoginGrantedBySession != parentRef {
		t.Errorf("vended LoginGrantedBySession = %q, want %q", vendedSess.LoginGrantedBySession, parentRef)
	}
	if vendedSess.EventsCount != 1 {
		t.Errorf("vended EventsCount = %d, want 1", vendedSess.EventsCount)
	}
}

// TestAwsLoginDifferentCreationDateNotTagged verifies a CreateOAuth2Token grant
// does NOT tag a session whose creationDate differs (exact-match key, no fuzz).
func TestAwsLoginDifferentCreationDateNotTagged(t *testing.T) {
	const (
		parentEmail    = "alex@engseclabs.com"
		roleID         = "AROAUB266OVZCWROZTVQR"
		roleARN        = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
		accountID      = "278835131762"
		parentCreation = "2026-04-16T17:43:08Z"
		otherCreation  = "2026-04-16T17:48:30Z"
	)
	stsARN := "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + parentEmail

	createTokenEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-16T17:43:26Z",
		EventName:   "CreateOAuth2Token",
		EventSource: "signin.amazonaws.com",
		UserAgent:   "aws-cli/2.34.30 md/command#login",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + parentEmail,
			ARN:            stsARN,
			AccountID:      accountID,
			SessionContext: makeSessionContext(parentCreation, roleARN),
		},
	}

	apiEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-16T17:51:00Z",
		EventName:   "ListUsers",
		EventSource: "iam.amazonaws.com",
		UserAgent:   "aws-cli/2.34.30 md/command#iam.list-users",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + parentEmail,
			ARN:            stsARN,
			AccountID:      accountID,
			AccessKeyID:    "ASIAUB266OVZDVEW755K",
			SessionContext: makeSessionContext(otherCreation, roleARN),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{createTokenEvent, apiEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	sessRef := ref("email#"+parentEmail, "key#ASIAUB266OVZDVEW755K", roleID)
	sess, ok := sessions[sessRef]
	if !ok {
		t.Fatalf("session %q not found; keys: %v", sessRef, sessionKeys(sessions))
	}
	if sess.SessionType == SessionTypeLogin {
		t.Errorf("SessionType = %q, should not be login (creationDate differs from the grant's)", sess.SessionType)
	}
	if sess.LoginGrantedBySession != "" {
		t.Errorf("LoginGrantedBySession = %q, want empty", sess.LoginGrantedBySession)
	}
}

// TestSsoLoginGetRoleCredentialsNotTagged verifies a regular aws sso login flow
// (GetRoleCredentials, not CreateOAuth2Token) is NOT tagged as "login".
func TestSsoLoginGetRoleCredentialsNotTagged(t *testing.T) {
	const (
		userEmail    = "alex@engseclabs.com"
		userRoleID   = "AROAUB266OVZNNBCMBRFT"
		userRoleARN  = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_SandboxPowerUser_50d858085657c5c1"
		accountID    = "278835131762"
		creationDate = "2026-04-16T17:39:11Z"
	)

	getRoleCredsEvent := types.CloudTrailRecord{
		EventTime:   creationDate,
		EventName:   "GetRoleCredentials",
		EventSource: "sso.amazonaws.com",
		UserAgent:   "aws-cli/2.34.30 md/command#sts.get-caller-identity",
		UserIdentity: types.UserIdentity{
			Type:      "IdentityCenterUser",
			AccountID: "843363563907",
		},
	}

	apiEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-16T17:39:17Z",
		EventName:   "ListBuckets",
		EventSource: "s3.amazonaws.com",
		UserAgent:   "aws-cli/2.34.30 md/command#s3.ls",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    userRoleID + ":" + userEmail,
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_SandboxPowerUser_50d858085657c5c1/" + userEmail,
			AccountID:      accountID,
			AccessKeyID:    "ASIAUB266OVZEKHQQZXJ",
			SessionContext: makeSessionContext(creationDate, userRoleARN),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{getRoleCredsEvent, apiEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	sessRef := ref("email#"+userEmail, "key#ASIAUB266OVZEKHQQZXJ", userRoleID)
	sess, ok := sessions[sessRef]
	if !ok {
		t.Fatalf("session %q not found; keys: %v", sessRef, sessionKeys(sessions))
	}
	if sess.SessionType != SessionTypeCLI {
		t.Errorf("SessionType = %q, want %q for aws sso login flow", sess.SessionType, SessionTypeCLI)
	}
	if sess.LoginGrantedBySession != "" {
		t.Errorf("LoginGrantedBySession = %q, want empty for aws sso login flow", sess.LoginGrantedBySession)
	}
	if sess.EventsCount != 1 {
		t.Errorf("EventsCount = %d, want 1", sess.EventsCount)
	}
}

// TestTaggedAssumeRoleAttribution verifies an AssumeRole carrying session tags
// propagates them to the child session record.
func TestTaggedAssumeRoleAttribution(t *testing.T) {
	const (
		humanEmail    = "alice@example.com"
		parentRoleID  = "AROAALICEPARENT12345"
		parentRoleARN = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		agentRoleARN  = "arn:aws:iam::111111111111:role/claude-code-agent"
		issuedKey     = "ASIAAGENTKEY00000001"
		creationDate  = "2026-04-20T14:00:00Z"
		accountID     = "111111111111"
	)

	agentAssumeRoleEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-20T14:30:00Z",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + humanEmail,
			ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc123/" + humanEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
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

	personKey := "email#" + humanEmail
	childRef := ref(personKey, "key#"+issuedKey, "AROAAGENTROLEID12345")
	childSess, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if childSess.SessionType != SessionTypeCLI {
		t.Errorf("child SessionType = %q, want %q", childSess.SessionType, SessionTypeCLI)
	}
	if childSess.SessionTags["AgentName"] != "claude-code" {
		t.Errorf("child SessionTags[AgentName] = %q, want \"claude-code\"", childSess.SessionTags["AgentName"])
	}
	if childSess.SessionTags["Task"] != "deploy-lambda" {
		t.Errorf("child SessionTags[Task] = %q, want \"deploy-lambda\"", childSess.SessionTags["Task"])
	}
	if childSess.SessionTags["HumanSession"] != humanEmail {
		t.Errorf("child SessionTags[HumanSession] = %q, want %q", childSess.SessionTags["HumanSession"], humanEmail)
	}
	if childSess.EventsCount != 1 {
		t.Errorf("child EventsCount = %d, want 1", childSess.EventsCount)
	}

	parentRef := ref(personKey, "web#"+parentRoleID+"#"+creationDate, parentRoleID)
	parentSess, ok := sessions[parentRef]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", parentRef, sessionKeys(sessions))
	}
	if parentSess.ChainedEventCount != 1 {
		t.Errorf("parent ChainedEventCount = %d, want 1", parentSess.ChainedEventCount)
	}
}

// TestMCPAgentSessionAttribution verifies the AWS MCP Server OAuth flow: a
// CreateOAuth2Token grant for the MCP Server registers an mcp# link, and API
// calls carrying the matching aws:SignInSessionArn anchor at sis#, resolve to
// the authorizing person at tier 2, and are typed "agent".
func TestMCPAgentSessionAttribution(t *testing.T) {
	const (
		userEmail        = "testuser@example.com"
		roleID           = "AROATJHQDX737YZPEXMPL"
		roleARN          = "arn:aws:iam::111111111111:role/Admin"
		accountID        = "111111111111"
		sourceIP         = "192.0.2.2"
		humanCreation    = "2026-06-09T05:06:39Z"
		mcpResource      = "https://aws-mcp.us-west-2.api.aws/mcp"
		signInSessionArn = "arn:aws:signin:us-west-2:111111111111:session/daff060f-7871-5tg6-67yu-a07bbdabe61a"
		agentCreation    = "2026-06-09T05:10:04Z"
		agentKey         = "ASIATJHQDX737MCPTOKEN"
	)
	assumedRoleARN := "arn:aws:sts::111111111111:assumed-role/Admin/" + userEmail

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
			SessionContext: makeSessionContext(humanCreation, roleARN),
		},
		RequestParameters: map[string]interface{}{
			"resource":  mcpResource,
			"client_id": "arn:aws:signin:us-west-2::external-client/dcr/609544da",
		},
	}

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
			"resource":  mcpResource,
			"client_id": "arn:aws:signin:us-west-2::external-client/dcr/609544da",
		},
		AdditionalEventData: map[string]interface{}{
			"signInSessionArn": signInSessionArn,
			"grant_type":       "refresh_token",
			"success":          "true",
		},
	}

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

	personKey := "email#" + userEmail
	humanRef := ref(personKey, "web#"+roleID+"#"+humanCreation, roleID)
	agentRef := ref(personKey, "sis#"+signInSessionArn, roleID)

	agentSess, ok := sessions[agentRef]
	if !ok {
		t.Fatalf("agent session %q not found; keys: %v", agentRef, sessionKeys(sessions))
	}
	if agentSess.SessionType != SessionTypeAgent {
		t.Errorf("agent SessionType = %q, want %q", agentSess.SessionType, SessionTypeAgent)
	}
	if agentSess.SignInSessionArn != signInSessionArn {
		t.Errorf("agent SignInSessionArn = %q, want %q", agentSess.SignInSessionArn, signInSessionArn)
	}
	if agentSess.MCPResource != mcpResource {
		t.Errorf("agent MCPResource = %q, want %q", agentSess.MCPResource, mcpResource)
	}
	if agentSess.AgentAuthorizedBySession != humanRef {
		t.Errorf("agent AgentAuthorizedBySession = %q, want %q", agentSess.AgentAuthorizedBySession, humanRef)
	}
	if agentSess.EventsCount != 1 {
		t.Errorf("agent EventsCount = %d, want 1 (grant must not inflate)", agentSess.EventsCount)
	}

	humanSess, ok := sessions[humanRef]
	if !ok {
		t.Fatalf("human session %q not found; keys: %v", humanRef, sessionKeys(sessions))
	}
	if humanSess.SessionType != SessionTypeWeb {
		t.Errorf("human SessionType = %q, want %q", humanSess.SessionType, SessionTypeWeb)
	}
}

// TestMCPAgentRotationOneSession verifies §8.1(10): agent credentials rotating
// under one signInSessionArn land in ONE sis# session.
func TestMCPAgentRotationOneSession(t *testing.T) {
	const (
		userEmail        = "testuser@example.com"
		roleID           = "AROATJHQDX737YZPEXMPL"
		roleARN          = "arn:aws:iam::111111111111:role/Admin"
		accountID        = "111111111111"
		humanCreation    = "2026-06-09T05:06:39Z"
		mcpResource      = "https://aws-mcp.us-west-2.api.aws/mcp"
		signInSessionArn = "arn:aws:signin:us-west-2:111111111111:session/multi-event-session"
	)
	assumedRoleARN := "arn:aws:sts::111111111111:assumed-role/Admin/" + userEmail

	createTokenEvent := types.CloudTrailRecord{
		EventTime:   "2026-06-09T05:10:04Z",
		EventName:   "CreateOAuth2Token",
		EventSource: "signin.amazonaws.com",
		UserAgent:   "curl/8.7.1",
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

	// Each call runs under a freshly rotated credential (new key, new creationDate).
	newAgentEvent := func(eventTime, name, src, key, creation string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: src,
			UserAgent:   "aws-mcp-server/1.0",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    roleID + ":" + userEmail,
				ARN:            assumedRoleARN,
				AccountID:      accountID,
				AccessKeyID:    key,
				SessionContext: makeSessionContextWithSignIn(creation, roleARN, signInSessionArn),
			},
		}
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		createTokenEvent,
		newAgentEvent("2026-06-09T05:12:31Z", "ListBuckets", "s3.amazonaws.com", "ASIAROTATION00000001", "2026-06-09T05:10:04Z"),
		newAgentEvent("2026-06-09T05:42:48Z", "DescribeInstances", "ec2.amazonaws.com", "ASIAROTATION00000002", "2026-06-09T05:40:00Z"),
		newAgentEvent("2026-06-09T06:13:02Z", "ListUsers", "iam.amazonaws.com", "ASIAROTATION00000003", "2026-06-09T06:10:00Z"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	agentRef := ref("email#"+userEmail, "sis#"+signInSessionArn, roleID)
	agentSess, ok := sessions[agentRef]
	if !ok {
		t.Fatalf("agent session %q not found; keys: %v", agentRef, sessionKeys(sessions))
	}
	if agentSess.SessionType != SessionTypeAgent {
		t.Errorf("agent SessionType = %q, want %q", agentSess.SessionType, SessionTypeAgent)
	}
	if agentSess.EventsCount != 3 {
		t.Errorf("agent EventsCount = %d, want 3 (rotation must not fragment the sis# session)", agentSess.EventsCount)
	}
}

// TestNonMCPOAuthTokenNotTaggedAgent verifies that a CreateOAuth2Token grant whose
// resource is NOT the AWS MCP Server does not produce an agent session — even
// when the session's events carry a signInSessionArn (which AWS is rolling out
// to ordinary sessions).
func TestNonMCPOAuthTokenNotTaggedAgent(t *testing.T) {
	const (
		userEmail        = "testuser@example.com"
		roleID           = "AROATJHQDX737YZPEXMPL"
		roleARN          = "arn:aws:iam::111111111111:role/Admin"
		accountID        = "111111111111"
		humanCreation    = "2026-06-09T05:06:39Z"
		signInSessionArn = "arn:aws:signin:us-west-2:111111111111:session/non-mcp-session"
		agentCreation    = "2026-06-09T05:10:04Z"
	)
	assumedRoleARN := "arn:aws:sts::111111111111:assumed-role/Admin/" + userEmail

	createTokenEvent := types.CloudTrailRecord{
		EventTime:   "2026-06-09T05:10:04Z",
		EventName:   "CreateOAuth2Token",
		EventSource: "signin.amazonaws.com",
		UserAgent:   "aws-cli/2.34.30 md/command#login",
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
		EventTime:   "2026-06-09T05:12:31Z",
		EventName:   "ListBuckets",
		EventSource: "s3.amazonaws.com",
		UserAgent:   "aws-cli/2.34.30 md/command#s3.ls",
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

	// The API event carries the arn in sessionContext, so it anchors sis# —
	// but with no mcp# link it must not be typed agent.
	sessRef := ref("email#"+userEmail, "sis#"+signInSessionArn, roleID)
	sess, ok := sessions[sessRef]
	if !ok {
		t.Fatalf("session %q not found; keys: %v", sessRef, sessionKeys(sessions))
	}
	if sess.SessionType == SessionTypeAgent {
		t.Errorf("SessionType = %q, must not be agent without an mcp# link", sess.SessionType)
	}
	if sess.MCPResource != "" {
		t.Errorf("MCPResource = %q, want empty for a non-MCP OAuth token", sess.MCPResource)
	}
}

// TestMCPAgentFixture drives testdata/aws_mcp_agent_session.json end-to-end,
// keeping the real captured AWS MCP Server flow and the aggregator in sync.
func TestMCPAgentFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "aws_mcp_agent_session.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var ctLog types.CloudTrailLog
	if err := json.Unmarshal(data, &ctLog); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	sessions, err := processForTest(ctLog.Records)
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	var agentSess *types.DynamoDBSession
	agentCount := 0
	for _, s := range sessions {
		if s.SessionType == SessionTypeAgent {
			agentSess = s
			agentCount++
		}
	}
	if agentSess == nil {
		t.Fatalf("no agent session produced from fixture; keys: %v", sessionKeys(sessions))
	}
	// Exactly one agent session — the CallReadWriteTool (keyless, console-shaped
	// credential) and ListUsers (rotated ASIA key) events must unify on the
	// sign-in session ARN, not split into two records.
	if agentCount != 1 {
		t.Errorf("agent session count = %d, want 1 (agent events must not split across sessions); keys: %v", agentCount, sessionKeys(sessions))
	}
	if agentSess.MCPResource != "https://aws-mcp.us-east-1.api.aws/mcp" {
		t.Errorf("MCPResource = %q, want the real us-east-1 MCP server resource", agentSess.MCPResource)
	}
	const wantArn = "arn:aws:signin:us-east-1:278835131762:session/a90e1d90-b08a-4ecf-ac06-e45576d13b98"
	if agentSess.SignInSessionArn != wantArn {
		t.Errorf("SignInSessionArn = %q, want the real captured arn", agentSess.SignInSessionArn)
	}
	if agentSess.Anchor != "sis#"+wantArn {
		t.Errorf("Anchor = %q, want sis#%s", agentSess.Anchor, wantArn)
	}
	if agentSess.PersonKey != "email#alex@engseclabs.com" {
		t.Errorf("PersonKey = %q, want email#alex@engseclabs.com", agentSess.PersonKey)
	}
	if !strings.HasPrefix(agentSess.AgentAuthorizedBySession, "email#alex@engseclabs.com|") {
		t.Errorf("AgentAuthorizedBySession = %q, want a ref under the authorizing person", agentSess.AgentAuthorizedBySession)
	}
	// Both agent events (CallReadWriteTool + ListUsers) aggregate here; the
	// CreateOAuth2Token grant is link-layer bookkeeping and must not inflate.
	if agentSess.EventsCount != 2 {
		t.Errorf("agent EventsCount = %d, want 2 (grant event must not inflate)", agentSess.EventsCount)
	}
}

// TestCLICredentialSpansHours verifies §8.1(1): one CLI credential spanning a
// 4-hour wall-clock boundary is ONE session — the pre-1.0 window-split bug,
// proven fixed (the anchor is the credential, not a time bucket).
func TestCLICredentialSpansHours(t *testing.T) {
	const (
		email        = "alice@example.com"
		roleID       = "AROAALICE12345678901"
		roleARN      = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Dev_abc"
		key          = "ASIAALICELONGSESSION"
		creationDate = "2026-07-15T09:55:00Z"
	)
	newEvent := func(eventTime, name string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: "s3.amazonaws.com",
			UserAgent:   "aws-cli/2.15.0",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    roleID + ":" + email,
				ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Dev_abc/" + email,
				AccountID:      "111111111111",
				AccessKeyID:    key,
				SessionContext: makeSessionContext(creationDate, roleARN),
			},
		}
	}

	// 10:00 and 15:30 straddle any 4-hour bucket boundary.
	sessions, err := processForTest([]types.CloudTrailRecord{
		newEvent("2026-07-15T10:00:00Z", "ListBuckets"),
		newEvent("2026-07-15T15:30:00Z", "GetObject"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1 (one credential = one session); keys: %v", len(sessions), sessionKeys(sessions))
	}
	sess := sessions[ref("email#"+email, "key#"+key, roleID)]
	if sess == nil {
		t.Fatalf("expected key# session not found; keys: %v", sessionKeys(sessions))
	}
	if sess.EventsCount != 2 {
		t.Errorf("EventsCount = %d, want 2", sess.EventsCount)
	}
	if sess.StartTime != "2026-07-15T10:00:00Z" || sess.EndTime != "2026-07-15T15:30:00Z" {
		t.Errorf("bounds = [%s, %s], want the true event bounds", sess.StartTime, sess.EndTime)
	}
}

// TestCredentialRefreshTwoSessions verifies §8.1(2): a credential refresh mints
// a new ASIA key → two sessions, same person on both. Deliberate v3 semantics.
func TestCredentialRefreshTwoSessions(t *testing.T) {
	const (
		email   = "alice@example.com"
		roleID  = "AROAALICE12345678901"
		roleARN = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Dev_abc"
	)
	newEvent := func(eventTime, key, creationDate string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   "ListBuckets",
			EventSource: "s3.amazonaws.com",
			UserAgent:   "aws-cli/2.15.0",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    roleID + ":" + email,
				ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Dev_abc/" + email,
				AccountID:      "111111111111",
				AccessKeyID:    key,
				SessionContext: makeSessionContext(creationDate, roleARN),
			},
		}
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		newEvent("2026-07-15T10:00:00Z", "ASIABEFOREREFRESH000", "2026-07-15T09:55:00Z"),
		newEvent("2026-07-15T11:00:01Z", "ASIAAFTERREFRESH0000", "2026-07-15T11:00:00Z"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2 (refresh = new session); keys: %v", len(sessions), sessionKeys(sessions))
	}
	for _, s := range sessions {
		if s.PersonKey != "email#"+email {
			t.Errorf("PersonKey = %q, want email#%s on both sessions", s.PersonKey, email)
		}
	}
}

// TestConsoleSessionOneWebSession verifies §8.1(3): a console session issuing a
// fresh access key per request but one creationDate is ONE web# session.
func TestConsoleSessionOneWebSession(t *testing.T) {
	const (
		email        = "alice@example.com"
		roleID       = "AROAALICE12345678901"
		roleARN      = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc"
		creationDate = "2026-07-15T09:00:00Z"
	)
	var events []types.CloudTrailRecord
	for i := 0; i < 7; i++ {
		e := types.CloudTrailRecord{
			EventTime:   "2026-07-15T09:0" + string(rune('0'+i)) + ":00Z",
			EventName:   "DescribeInstances",
			EventSource: "ec2.amazonaws.com",
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    roleID + ":" + email,
				ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc/" + email,
				AccountID:      "111111111111",
				AccessKeyID:    "ASIAPERREQUESTKEY00" + string(rune('0'+i)),
				SessionContext: makeSessionContext(creationDate, roleARN),
			},
		}
		e.UserIdentity.SessionContext.Attributes.SessionCredentialFromConsole = "true"
		// Only one event carries onBehalfOf (C1) — the group resolves tier 1.
		if i == 3 {
			e.UserIdentity.OnBehalfOf = &types.OnBehalfOf{
				UserID:           "94482488-3041-7098-e2a1-4d3c9c7e0b21",
				IdentityStoreARN: "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f",
			}
		}
		events = append(events, e)
	}

	sessions, err := processForTest(events)
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1 (per-request keys must not split a console session); keys: %v", len(sessions), sessionKeys(sessions))
	}
	personKey := identity.IdentityCenterPersonKey(
		"arn:aws:identitystore::278835131762:identitystore/d-9967750e0f",
		"94482488-3041-7098-e2a1-4d3c9c7e0b21")
	sess := sessions[ref(personKey, "web#"+roleID+"#"+creationDate, roleID)]
	if sess == nil {
		t.Fatalf("expected web# session under the tier-1 person; keys: %v", sessionKeys(sessions))
	}
	if sess.SessionType != SessionTypeWeb {
		t.Errorf("SessionType = %q, want %q", sess.SessionType, SessionTypeWeb)
	}
	if sess.EventsCount != 7 {
		t.Errorf("EventsCount = %d, want 7", sess.EventsCount)
	}
}

// TestAKIAWindowedFallback verifies §8.1(8): an IAM user on a long-lived AKIA
// key has no credential boundary — two bouts of activity an hour apart become
// two win# sessions under the iamuser# person.
func TestAKIAWindowedFallback(t *testing.T) {
	newEvent := func(eventTime string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   "ListBuckets",
			EventSource: "s3.amazonaws.com",
			UserAgent:   "aws-cli/2.15.0",
			UserIdentity: types.UserIdentity{
				Type:        "IAMUser",
				PrincipalID: "AIDADEPLOYBOT1234567",
				ARN:         "arn:aws:iam::111111111111:user/deploy-bot",
				AccountID:   "111111111111",
				AccessKeyID: "AKIADEPLOYBOT0000001",
				UserName:    "deploy-bot",
			},
		}
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		newEvent("2026-07-15T10:00:00Z"),
		newEvent("2026-07-15T10:10:00Z"),
		// 90 minutes idle — well past the 30m gap.
		newEvent("2026-07-15T11:40:00Z"),
		newEvent("2026-07-15T11:50:00Z"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2 win# sessions; keys: %v", len(sessions), sessionKeys(sessions))
	}
	personKey := "iamuser#arn:aws:iam::111111111111:user/deploy-bot"
	wantSKs := map[string]int{
		"win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z": 2,
		"win#AIDADEPLOYBOT1234567#2026-07-15T11:40:00Z": 2,
	}
	for sk, wantEvents := range wantSKs {
		sess := sessions[identity.SessionRef(personKey, sk)]
		if sess == nil {
			t.Errorf("windowed session %q not found; keys: %v", sk, sessionKeys(sessions))
			continue
		}
		if sess.EventsCount != wantEvents {
			t.Errorf("session %q EventsCount = %d, want %d", sk, sess.EventsCount, wantEvents)
		}
		if sess.SessionType != SessionTypeCLI {
			t.Errorf("session %q SessionType = %q, want %q", sk, sess.SessionType, SessionTypeCLI)
		}
	}
}

// TestInvokedByServiceDriven verifies §8.1(12): events with userIdentity.invokedBy
// join the person's session, count in service_driven_event_count, and are
// excluded from ClickOps flagging.
func TestInvokedByServiceDriven(t *testing.T) {
	const (
		email        = "alice@example.com"
		roleID       = "AROAALICE12345678901"
		roleARN      = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc"
		creationDate = "2026-07-15T09:00:00Z"
		browserUA    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
	)
	newConsoleEvent := func(eventTime, name, invokedBy string) types.CloudTrailRecord {
		e := types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: "s3.amazonaws.com",
			UserAgent:   browserUA,
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    roleID + ":" + email,
				ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc/" + email,
				AccountID:      "111111111111",
				InvokedBy:      invokedBy,
				SessionContext: makeSessionContext(creationDate, roleARN),
			},
		}
		e.UserIdentity.SessionContext.Attributes.SessionCredentialFromConsole = "true"
		return e
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		newConsoleEvent("2026-07-15T09:01:00Z", "CreateBucket", ""),
		newConsoleEvent("2026-07-15T09:02:00Z", "CreateBucket", "cloudformation.amazonaws.com"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	sess := sessions[ref("email#"+email, "web#"+roleID+"#"+creationDate, roleID)]
	if sess == nil {
		t.Fatalf("web session not found; keys: %v", sessionKeys(sessions))
	}
	if sess.EventsCount != 2 {
		t.Errorf("EventsCount = %d, want 2 (invokedBy events join the session)", sess.EventsCount)
	}
	if sess.ServiceDrivenEventCount != 1 {
		t.Errorf("ServiceDrivenEventCount = %d, want 1", sess.ServiceDrivenEventCount)
	}
	if sess.ClickOpsEventCount != 1 {
		t.Errorf("ClickOpsEventCount = %d, want 1 (the human click only, not the CloudFormation fan-out)", sess.ClickOpsEventCount)
	}
}

// TestEventIDDedupe verifies §3.3 in-batch dedupe: org trails duplicate
// global-service events across region files; repeated eventIDs count once.
func TestEventIDDedupe(t *testing.T) {
	const (
		email   = "alice@example.com"
		roleID  = "AROAALICE12345678901"
		roleARN = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Dev_abc"
	)
	event := types.CloudTrailRecord{
		EventID:     "11111111-2222-3333-4444-555555555555",
		EventTime:   "2026-07-15T10:00:00Z",
		EventName:   "ListRoles",
		EventSource: "iam.amazonaws.com",
		AwsRegion:   "us-east-1",
		UserAgent:   "aws-cli/2.15.0",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    roleID + ":" + email,
			ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Dev_abc/" + email,
			AccountID:      "111111111111",
			AccessKeyID:    "ASIAALICEDEDUPE00001",
			SessionContext: makeSessionContext("2026-07-15T09:55:00Z", roleARN),
		},
	}
	duplicate := event
	duplicate.AwsRegion = "us-west-2" // same event delivered in another region file

	sessions, err := processForTest([]types.CloudTrailRecord{event, duplicate})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	sess := sessions[ref("email#"+email, "key#ASIAALICEDEDUPE00001", roleID)]
	if sess == nil {
		t.Fatalf("session not found; keys: %v", sessionKeys(sessions))
	}
	if sess.EventsCount != 1 {
		t.Errorf("EventsCount = %d, want 1 (duplicate eventID must count once)", sess.EventsCount)
	}
}
