// AWS MCP Server OAuth flow: agent typing, credential-rotation unification,
// the mcp#-link-only guard, and the real captured fixture.
package aggregator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

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
