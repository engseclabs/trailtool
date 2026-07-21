// AWS MCP Server OAuth flow: agent typing, credential-rotation unification,
// the mcp#-link-only guard, and the real captured fixture.
package aggregator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
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
	// Symmetric grant ref: the authorizing session records the agent session.
	if len(humanSess.GrantedSessionRefs) != 1 || humanSess.GrantedSessionRefs[0] != agentRef {
		t.Errorf("human GrantedSessionRefs = %v, want [%s]", humanSess.GrantedSessionRefs, agentRef)
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

// TestTwoAgentsUnderOneConsoleSession is the sandbox regression: from one
// browser console session a developer starts two MCP agents. Both grants
// (CreateOAuth2Token) and both agents' API calls share the console session's
// principalId + creationDate — and the grant events carry no access key — so
// before the sig# split they collapsed into one credential group whose single
// anchor swallowed the console session and both agents, and the grants
// attributed the agents to an agent session instead of the human. This
// verifies the console session and each agent land in distinct sessions, each
// agent points back at the human, and the human lists both as granted.
func TestTwoAgentsUnderOneConsoleSession(t *testing.T) {
	const (
		email        = "alex@engseclabs.com"
		roleID       = "AROAUB266OVZCWROZTVQR"
		roleARN      = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
		accountID    = "278835131762"
		creationDate = "2026-07-20T20:02:06Z" // shared by console + both agents
		mcpResource  = "https://aws-mcp.us-east-1.api.aws/mcp"
		arnA         = "arn:aws:signin:us-east-1:278835131762:session/758bfa40-dfc0-4094-8c2d-6a3a6bd78222"
		arnB         = "arn:aws:signin:us-east-1:278835131762:session/7aa5faf9-bfc1-4518-8cdf-bb090ef4a2a2"
		storeARN     = "arn:aws:identitystore::843363563907:identitystore/d-9a675246c6"
		userID       = "11fb6570-3051-707e-a14f-d5a0d1f455fe"
	)
	principal := roleID + ":" + email
	stsARN := "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + email
	obo := &types.OnBehalfOf{UserID: userID, IdentityStoreARN: storeARN}

	// A browser console event (flagged), establishing the web# session.
	consoleEvent := types.CloudTrailRecord{
		EventTime:   "2026-07-20T20:02:10Z",
		EventName:   "DescribeRegions",
		EventSource: "ec2.amazonaws.com",
		UserAgent:   "Mozilla/5.0 (Macintosh) Safari/605.1.15",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    principal,
			ARN:            stsARN,
			AccountID:      accountID,
			OnBehalfOf:     obo,
			SessionContext: makeSessionContext(creationDate, roleARN),
		},
	}
	consoleEvent.UserIdentity.SessionContext.Attributes.SessionCredentialFromConsole = "true"

	// Grant for each agent: no access key, carries the console creationDate,
	// signInSessionArn only in additionalEventData.
	grant := func(eventTime, arn string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   "CreateOAuth2Token",
			EventSource: "signin.amazonaws.com",
			UserAgent:   "Bun/1.4.0",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    principal,
				ARN:            stsARN,
				AccountID:      accountID,
				OnBehalfOf:     obo,
				SessionContext: makeSessionContext(creationDate, roleARN),
			},
			RequestParameters:   map[string]interface{}{"resource": mcpResource},
			AdditionalEventData: map[string]interface{}{"signInSessionArn": arn},
		}
	}

	// Agent API call: carries the arn in sessionContext AND the console
	// creationDate; access key rotates per request.
	agentCall := func(eventTime, arn, name, key string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: "iam.amazonaws.com",
			UserAgent:   "aws-mcp.amazonaws.com",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    principal,
				ARN:            stsARN,
				AccountID:      accountID,
				AccessKeyID:    key,
				OnBehalfOf:     obo,
				SessionContext: makeSessionContextWithSignIn(creationDate, roleARN, arn),
			},
		}
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		consoleEvent,
		grant("2026-07-20T20:02:13Z", arnA),
		agentCall("2026-07-20T20:02:20Z", arnA, "ListRoles", "ASIAAGENTAROTKEY001"),
		agentCall("2026-07-20T20:02:25Z", arnA, "ListUsers", "ASIAAGENTAROTKEY002"),
		grant("2026-07-20T20:19:57Z", arnB),
		agentCall("2026-07-20T20:20:05Z", arnB, "GetSAMLProvider", ""), // keyless agent event
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := identity.IdentityCenterPersonKey(storeARN, userID)
	webRef := ref(personKey, "web#"+roleID+"#"+creationDate, roleID)
	agentARef := ref(personKey, "sis#"+arnA, roleID)
	agentBRef := ref(personKey, "sis#"+arnB, roleID)

	if len(sessions) != 3 {
		t.Fatalf("got %d sessions, want 3 (1 web + 2 agents); keys: %v", len(sessions), sessionKeys(sessions))
	}

	web, ok := sessions[webRef]
	if !ok {
		t.Fatalf("web session %q not found; keys: %v", webRef, sessionKeys(sessions))
	}
	if web.SessionType != SessionTypeWeb {
		t.Errorf("console SessionType = %q, want web", web.SessionType)
	}
	// The human authorized both agents.
	if len(web.GrantedSessionRefs) != 2 {
		t.Errorf("web GrantedSessionRefs = %v, want both agent refs", web.GrantedSessionRefs)
	}
	for _, want := range []string{agentARef, agentBRef} {
		found := false
		for _, g := range web.GrantedSessionRefs {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("web GrantedSessionRefs missing %s; got %v", want, web.GrantedSessionRefs)
		}
	}

	for _, tc := range []struct {
		name, refKey string
		events       int
	}{
		{"agentA", agentARef, 2},
		{"agentB", agentBRef, 1},
	} {
		a, ok := sessions[tc.refKey]
		if !ok {
			t.Errorf("%s session %q not found", tc.name, tc.refKey)
			continue
		}
		if a.SessionType != SessionTypeAgent {
			t.Errorf("%s SessionType = %q, want agent", tc.name, a.SessionType)
		}
		if a.AgentAuthorizedBySession != webRef {
			t.Errorf("%s AgentAuthorizedBySession = %q, want the human web session %q", tc.name, a.AgentAuthorizedBySession, webRef)
		}
		if a.EventsCount != tc.events {
			t.Errorf("%s EventsCount = %d, want %d", tc.name, a.EventsCount, tc.events)
		}
		if a.MCPResource != mcpResource {
			t.Errorf("%s MCPResource = %q, want %q", tc.name, a.MCPResource, mcpResource)
		}
	}
}
