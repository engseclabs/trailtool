// Cross-batch link resolution: a credential group's events landing in a later
// S3 file than the events (or grants) that identify them, simulated by seeding
// resolveGroups with stored identity links.
package aggregator

import (
	"context"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// aggregateForTest runs aggregation with injected stored links (as if fetched
// from trailtool-identity-links) and no DynamoDB client.
func aggregateForTest(events []types.CloudTrailRecord, stored map[string]*link) (map[string]*types.DynamoDBSession, error) {
	return aggregateGroups(context.Background(), nil, Config{Namespace: "test"}, "test",
		identity.GroupEvents(dedupeByEventID(events)), stored)
}

const (
	xbStoreARN  = "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f"
	xbUserID    = "94482488-3041-7098-e2a1-4d3c9c7e0b21"
	xbRoleID    = "AROAUB266OVZCWROZTVQR"
	xbRoleARN   = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
	xbAccountID = "278835131762"
)

// xbCLIEvent builds a bare CLI event with no onBehalfOf and no email in the
// session name — resolvable only through a link.
func xbCLIEvent(eventTime, name, accessKey, creationDate string) types.CloudTrailRecord {
	return types.CloudTrailRecord{
		EventTime:   eventTime,
		EventName:   name,
		EventSource: "s3.amazonaws.com",
		UserAgent:   "aws-cli/2.15.0",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    xbRoleID + ":awsuser",
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/awsuser",
			AccountID:      xbAccountID,
			AccessKeyID:    accessKey,
			SessionContext: makeSessionContext(creationDate, xbRoleARN),
		},
	}
}

// §8.1(5) — C1 cross-batch: batch A resolved ak#X at tier 1 with anchor sis#S
// and wrote a cred#X link; batch B has ak#X events with no onBehalfOf and no
// signInSessionArn. The cred# link must yield the same person AND the same
// session (anchor continuity).
func TestCrossBatchCredLinkResolvesPersonAndAnchor(t *testing.T) {
	personKey := identity.IdentityCenterPersonKey(xbStoreARN, xbUserID)
	const sisAnchor = "sis#arn:aws:signin:us-east-1:278835131762:session/batch-a-session"

	stored := map[string]*link{
		"cred#ASIAXBATCHCRED00001": {
			kind:      linkCred,
			personKey: personKey,
			anchor:    sisAnchor,
			stored:    true,
			pks:       []string{"cred#ASIAXBATCHCRED00001"},
		},
	}

	sessions, err := aggregateForTest([]types.CloudTrailRecord{
		xbCLIEvent("2026-07-15T10:00:00Z", "ListBuckets", "ASIAXBATCHCRED00001", "2026-07-15T09:55:00Z"),
		xbCLIEvent("2026-07-15T10:05:00Z", "GetObject", "ASIAXBATCHCRED00001", "2026-07-15T09:55:00Z"),
	}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}

	wantRef := identity.SessionRef(personKey, identity.SessionSK(sisAnchor, xbRoleID))
	sess, ok := sessions[wantRef]
	if !ok {
		t.Fatalf("session %q not found — cred# link did not carry person+anchor; keys: %v", wantRef, sessionKeys(sessions))
	}
	if sess.PersonKey != personKey {
		t.Errorf("PersonKey = %q, want the tier-1 person from batch A", sess.PersonKey)
	}
	if sess.EventsCount != 2 {
		t.Errorf("EventsCount = %d, want 2", sess.EventsCount)
	}
	if len(sessions) != 1 {
		t.Errorf("got %d sessions, want 1", len(sessions))
	}
}

// Anchor continuity also holds in the other direction: batch A anchored key#X
// (no signInSessionArn yet), batch B's events of the same credential now carry
// one. The stored anchor must win or the credential splits across two sessions.
func TestCrossBatchAnchorContinuityBeatsCascade(t *testing.T) {
	personKey := identity.IdentityCenterPersonKey(xbStoreARN, xbUserID)
	const key = "ASIAXBATCHCONT00001"

	stored := map[string]*link{
		"cred#" + key: {
			kind:      linkCred,
			personKey: personKey,
			anchor:    "key#" + key,
			stored:    true,
			pks:       []string{"cred#" + key},
		},
	}

	e := xbCLIEvent("2026-07-15T10:00:00Z", "ListBuckets", key, "2026-07-15T09:55:00Z")
	e.UserIdentity.SessionContext.SignInSessionArn = "arn:aws:signin:us-east-1:278835131762:session/late-stamped"

	sessions, err := aggregateForTest([]types.CloudTrailRecord{e}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}

	wantRef := identity.SessionRef(personKey, identity.SessionSK("key#"+key, xbRoleID))
	if _, ok := sessions[wantRef]; !ok {
		t.Fatalf("session %q not found — cascade overrode the stored anchor; keys: %v", wantRef, sessionKeys(sessions))
	}
	if len(sessions) != 1 {
		t.Errorf("got %d sessions, want 1 (credential must not split across anchors)", len(sessions))
	}
}

// Cross-batch role chaining: the AssumeRole landed in batch A (which wrote the
// chain# link); batch B has only the child credential's events.
func TestCrossBatchChainLinkAttributesChild(t *testing.T) {
	const (
		personKey      = "email#alice@example.com"
		issuedKey      = "ASIAXBATCHCHAIN0001"
		parentRef      = "email#alice@example.com|web#AROAALICEPARENT12345#2026-07-15T09:00:00Z#AROAALICEPARENT12345"
		parentRoleARN  = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		assumedRoleARN = "arn:aws:iam::333333333333:role/ReadOnlyRole"
	)

	stored := map[string]*link{
		"chain#" + issuedKey: {
			kind:             linkChain,
			personKey:        personKey,
			parentSessionRef: parentRef,
			parentRoleARN:    parentRoleARN,
			assumedRoleARN:   assumedRoleARN,
			sessionTags:      map[string]string{"AgentName": "claude-code"},
			stored:           true,
			pks:              []string{"chain#" + issuedKey},
		},
	}

	childEvent := types.CloudTrailRecord{
		EventTime:   "2026-07-15T09:10:00Z",
		EventName:   "ListBuckets",
		EventSource: "s3.amazonaws.com",
		UserAgent:   "aws-cli/2.15.0",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAREADONLY:read-session",
			ARN:         "arn:aws:sts::333333333333:assumed-role/ReadOnlyRole/read-session",
			AccountID:   "333333333333",
			AccessKeyID: issuedKey,
		},
	}

	sessions, err := aggregateForTest([]types.CloudTrailRecord{childEvent}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}

	childRef := identity.SessionRef(personKey, identity.SessionSK("key#"+issuedKey, "AROAREADONLY"))
	child, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if child.AssumedFromSession != parentRef {
		t.Errorf("AssumedFromSession = %q, want %q", child.AssumedFromSession, parentRef)
	}
	if child.AssumedFromRoleARN != parentRoleARN {
		t.Errorf("AssumedFromRoleARN = %q, want %q", child.AssumedFromRoleARN, parentRoleARN)
	}
	if child.RoleARN != assumedRoleARN {
		t.Errorf("RoleARN = %q, want %q", child.RoleARN, assumedRoleARN)
	}
	if child.SessionTags["AgentName"] != "claude-code" {
		t.Errorf("SessionTags[AgentName] = %q, want claude-code (propagated from the stored link)", child.SessionTags["AgentName"])
	}
}

// Cross-batch MCP: the CreateOAuth2Token grant landed in an earlier file; the
// agent's API calls carry only the signInSessionArn.
func TestCrossBatchMCPLinkTypesAgent(t *testing.T) {
	const (
		personKey   = "email#alex@engseclabs.com"
		sisArn      = "arn:aws:signin:us-east-1:278835131762:session/xbatch-mcp"
		mcpResource = "https://aws-mcp.us-east-1.api.aws/mcp"
		humanRef    = "email#alex@engseclabs.com|web#" + xbRoleID + "#2026-07-15T09:00:00Z#" + xbRoleID
	)

	stored := map[string]*link{
		"mcp#" + sisArn: {
			kind:             linkMCP,
			personKey:        personKey,
			parentSessionRef: humanRef,
			mcpResource:      mcpResource,
			stored:           true,
			pks:              []string{"mcp#" + sisArn},
		},
	}

	e := xbCLIEvent("2026-07-15T10:00:00Z", "ListBuckets", "ASIAXBATCHMCP000001", "2026-07-15T09:58:00Z")
	e.UserIdentity.SessionContext.SignInSessionArn = sisArn

	sessions, err := aggregateForTest([]types.CloudTrailRecord{e}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}

	agentRef := identity.SessionRef(personKey, identity.SessionSK("sis#"+sisArn, xbRoleID))
	agent, ok := sessions[agentRef]
	if !ok {
		t.Fatalf("agent session %q not found; keys: %v", agentRef, sessionKeys(sessions))
	}
	if agent.SessionType != SessionTypeAgent {
		t.Errorf("SessionType = %q, want %q", agent.SessionType, SessionTypeAgent)
	}
	if agent.MCPResource != mcpResource {
		t.Errorf("MCPResource = %q, want %q", agent.MCPResource, mcpResource)
	}
	if agent.AgentAuthorizedBySession != humanRef {
		t.Errorf("AgentAuthorizedBySession = %q, want %q", agent.AgentAuthorizedBySession, humanRef)
	}
}

// Cross-batch service fan-out: the human's session landed in an earlier file;
// this batch has only forward-access events (invokedBy, per-request keys).
// The stored cred#<principalId>#<creationDate> link routes them into the
// originating key# session.
func TestCrossBatchFanOutJoinsOriginViaCredLink(t *testing.T) {
	personKey := identity.IdentityCenterPersonKey(xbStoreARN, xbUserID)
	const (
		humanKey     = "ASIAXBATCHORIGIN001"
		creationDate = "2026-07-17T20:43:51Z"
	)
	principal := xbRoleID + ":awsuser"

	stored := map[string]*link{
		"cred#" + principal + "#" + creationDate: {
			kind:      linkCred,
			personKey: personKey,
			anchor:    "key#" + humanKey,
			stored:    true,
			pks:       []string{"cred#" + principal + "#" + creationDate},
		},
	}

	fanOut := xbCLIEvent("2026-07-17T20:50:00Z", "DescribeTable", "ASIAFANOUTLATE00001", creationDate)
	fanOut.UserIdentity.InvokedBy = "cloudformation.amazonaws.com"

	sessions, err := aggregateForTest([]types.CloudTrailRecord{fanOut}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}

	wantRef := identity.SessionRef(personKey, identity.SessionSK("key#"+humanKey, xbRoleID))
	sess, ok := sessions[wantRef]
	if !ok {
		t.Fatalf("session %q not found — fan-out did not join the origin session; keys: %v", wantRef, sessionKeys(sessions))
	}
	if sess.ServiceDrivenEventCount != 1 {
		t.Errorf("ServiceDrivenEventCount = %d, want 1", sess.ServiceDrivenEventCount)
	}
	if len(sessions) != 1 {
		t.Errorf("got %d sessions, want 1", len(sessions))
	}
}

// Cross-batch aws login: the grant landed in an earlier file; the vended
// credential's events match by roleID + creationDate.
func TestCrossBatchLoginLinkTypesLogin(t *testing.T) {
	const (
		personKey = "email#alex@engseclabs.com"
		grantCD   = "2026-07-15T09:55:00Z"
		parentRef = "email#alex@engseclabs.com|web#" + xbRoleID + "#" + grantCD + "#" + xbRoleID
	)

	stored := map[string]*link{
		"login#" + xbRoleID + "#" + grantCD: {
			kind:             linkLogin,
			personKey:        personKey,
			parentSessionRef: parentRef,
			stored:           true,
			pks:              []string{"login#" + xbRoleID + "#" + grantCD},
		},
	}

	sessions, err := aggregateForTest([]types.CloudTrailRecord{
		xbCLIEvent("2026-07-15T10:00:00Z", "ListUsers", "ASIAXBATCHLOGIN0001", grantCD),
	}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}

	vendedRef := identity.SessionRef(personKey, identity.SessionSK("key#ASIAXBATCHLOGIN0001", xbRoleID))
	vended, ok := sessions[vendedRef]
	if !ok {
		t.Fatalf("vended session %q not found; keys: %v", vendedRef, sessionKeys(sessions))
	}
	if vended.SessionType != SessionTypeLogin {
		t.Errorf("SessionType = %q, want %q", vended.SessionType, SessionTypeLogin)
	}
	if vended.LoginGrantedBySession != parentRef {
		t.Errorf("LoginGrantedBySession = %q, want %q", vended.LoginGrantedBySession, parentRef)
	}
}
