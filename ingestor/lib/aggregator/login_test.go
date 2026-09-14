// aws login (PKCE OAuth) grant attribution and its non-matches.
package aggregator

import (
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// TestAwsLoginSessionDetection verifies the aws login (PKCE OAuth2) flow: the
// CreateOAuth2Token grant registers a login# link, and the vended credential's
// session (key# anchor, same roleID+creationDate) is typed "login" with
// login_granted_by_session pointing at the authorizing session. The authorizing
// web session itself stays typed "web".
func TestAwsLoginSessionDetection(t *testing.T) {
	const (
		parentEmail    = "test-user@example.invalid"
		roleID         = "AROAEXAMPLE0000000000"
		roleARN        = "arn:aws:iam::000000000000:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_TestAccess_0000000000000000"
		sourceIP       = "192.0.2.1"
		accountID      = "000000000000"
		parentCreation = "2026-04-16T17:43:08Z"
		vendedKey      = "ASIAEXAMPLE000000000"
	)
	stsARN := "arn:aws:sts::000000000000:assumed-role/AWSReservedSSO_TestAccess_0000000000000000/" + parentEmail

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
	// Symmetric grant ref: the authorizing session records the vended session.
	if len(parentSess.GrantedSessionRefs) != 1 || parentSess.GrantedSessionRefs[0] != vendedRef {
		t.Errorf("authorizing GrantedSessionRefs = %v, want [%s]", parentSess.GrantedSessionRefs, vendedRef)
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
		parentEmail    = "test-user@example.invalid"
		roleID         = "AROAEXAMPLE0000000000"
		roleARN        = "arn:aws:iam::000000000000:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_TestAccess_0000000000000000"
		accountID      = "000000000000"
		parentCreation = "2026-04-16T17:43:08Z"
		otherCreation  = "2026-04-16T17:48:30Z"
	)
	stsARN := "arn:aws:sts::000000000000:assumed-role/AWSReservedSSO_TestAccess_0000000000000000/" + parentEmail

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
			AccessKeyID:    "ASIAEXAMPLE000000000",
			SessionContext: makeSessionContext(otherCreation, roleARN),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{createTokenEvent, apiEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	sessRef := ref("email#"+parentEmail, "key#ASIAEXAMPLE000000000", roleID)
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
		userEmail    = "test-user@example.invalid"
		userRoleID   = "AROAEXAMPLE0000000001"
		userRoleARN  = "arn:aws:iam::000000000000:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_TestPowerUser_0000000000000001"
		accountID    = "000000000000"
		creationDate = "2026-04-16T17:39:11Z"
	)

	getRoleCredsEvent := types.CloudTrailRecord{
		EventTime:   creationDate,
		EventName:   "GetRoleCredentials",
		EventSource: "sso.amazonaws.com",
		UserAgent:   "aws-cli/2.34.30 md/command#sts.get-caller-identity",
		UserIdentity: types.UserIdentity{
			Type:      "IdentityCenterUser",
			AccountID: "000000000001",
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
			ARN:            "arn:aws:sts::000000000000:assumed-role/AWSReservedSSO_TestPowerUser_0000000000000001/" + userEmail,
			AccountID:      accountID,
			AccessKeyID:    "ASIAEXAMPLE000000001",
			SessionContext: makeSessionContext(creationDate, userRoleARN),
		},
	}

	sessions, err := processForTest([]types.CloudTrailRecord{getRoleCredsEvent, apiEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	sessRef := ref("email#"+userEmail, "key#ASIAEXAMPLE000000001", userRoleID)
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
