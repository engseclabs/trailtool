package aggregator

import (
	"reflect"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const (
	aamEventTime     = "2026-08-21T21:05:11Z"
	aamRoleID        = "AROAEXAMPLE0000000002"
	aamSessionName   = "00000000-0000-4000-8000-000000000001"
	aamPrincipalID   = aamRoleID + ":" + aamSessionName
	aamRoleARN       = "arn:aws:iam::000000000000:role/aam-test-role"
	aamStoreARN      = "arn:aws:identitystore::000000000001:identitystore/d-0000000000"
	aamUserID        = "00000000-0000-4000-8000-000000000001"
	aamDownstreamKey = "ASIAAAMDOWNSTREAM001"
)

// Identifiers in this file are synthetic; AWS-shaped values use EXAMPLE or
// zero-filled components so they cannot be mistaken for deployable credentials.
var aamTags = map[string]string{
	"email":      "test-user@example.invalid",
	"department": "security",
}

// aamAssumeRoleEvent models the service-side STS event observed for an
// Account Access Management login. Its AWSService identity cannot resolve to a
// human on its own; the response identifies the session that receives tags.
func aamAssumeRoleEvent() types.CloudTrailRecord {
	return types.CloudTrailRecord{
		EventID:     "00000000-0000-4000-8000-000000000201",
		EventTime:   aamEventTime,
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		AwsRegion:   "us-east-2",
		UserAgent:   "account-access.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:      "AWSService",
			InvokedBy: "account-access.amazonaws.com",
		},
		RequestParameters: map[string]interface{}{
			"roleArn":         aamRoleARN,
			"roleSessionName": aamSessionName,
			"tags": []interface{}{
				map[string]interface{}{"key": "email", "value": aamTags["email"]},
				map[string]interface{}{"key": "department", "value": aamTags["department"]},
			},
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId": "ASIAAAMISSUEDKEY001",
			},
			"assumedRoleUser": map[string]interface{}{
				"assumedRoleId": aamPrincipalID,
				"arn":           "arn:aws:sts::000000000000:assumed-role/aam-test-role/" + aamSessionName,
			},
		},
	}
}

func aamSessionContext(console bool) *types.SessionContext {
	sc := makeSessionContext(aamEventTime, aamRoleARN)
	if console {
		sc.Attributes.SessionCredentialFromConsole = "true"
	}
	return sc
}

func aamIdentity(console bool, accessKey string) types.UserIdentity {
	return types.UserIdentity{
		Type:           "AssumedRole",
		PrincipalID:    aamPrincipalID,
		ARN:            "arn:aws:sts::000000000000:assumed-role/aam-test-role/" + aamSessionName,
		AccountID:      "000000000000",
		AccessKeyID:    accessKey,
		SessionContext: aamSessionContext(console),
		OnBehalfOf: &types.OnBehalfOf{
			UserID:           aamUserID,
			IdentityStoreARN: aamStoreARN,
		},
	}
}

func aamDownstreamEvent() types.CloudTrailRecord {
	return types.CloudTrailRecord{
		EventID:         "00000000-0000-4000-8000-000000000202",
		EventTime:       "2026-08-21T21:05:14Z",
		EventName:       "ListBuckets",
		EventSource:     "s3.amazonaws.com",
		AwsRegion:       "us-east-1",
		UserAgent:       "Mozilla/5.0 Safari/605.1.15",
		UserIdentity:    aamIdentity(true, aamDownstreamKey),
		SourceIPAddress: "192.0.2.1",
	}
}

func aamSessionRef() string {
	personKey := identity.IdentityCenterPersonKey(aamStoreARN, aamUserID)
	return identity.SessionRef(personKey, identity.SessionSK("web#"+aamRoleID+"#"+aamEventTime, aamRoleID))
}

func assertAAMSessionTags(t *testing.T, sessions map[string]*types.DynamoDBSession) {
	t.Helper()
	sess := sessions[aamSessionRef()]
	if sess == nil {
		t.Fatalf("AAM session %q not found; keys: %v", aamSessionRef(), sessionKeys(sessions))
	}
	if !reflect.DeepEqual(sess.SessionTags, aamTags) {
		t.Errorf("SessionTags = %v, want %v", sess.SessionTags, aamTags)
	}
	if sess.EventsCount != 1 {
		t.Errorf("EventsCount = %d, want 1 (AAM AssumeRole is metadata, not activity)", sess.EventsCount)
	}
	if sess.AssumedFromSession != "" {
		t.Errorf("AssumedFromSession = %q, want empty (AAM issuance is not role chaining)", sess.AssumedFromSession)
	}
}

func TestAAMSessionTagsCorrelateInBatchRegardlessOfEventOrder(t *testing.T) {
	for _, tt := range []struct {
		name   string
		events []types.CloudTrailRecord
	}{
		{name: "creation metadata first", events: []types.CloudTrailRecord{aamAssumeRoleEvent(), aamDownstreamEvent()}},
		{name: "downstream activity first", events: []types.CloudTrailRecord{aamDownstreamEvent(), aamAssumeRoleEvent()}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := processForTest(tt.events)
			if err != nil {
				t.Fatalf("processForTest() error: %v", err)
			}
			if len(sessions) != 1 {
				t.Fatalf("got %d sessions, want 1; keys: %v", len(sessions), sessionKeys(sessions))
			}
			assertAAMSessionTags(t, sessions)
		})
	}
}

func TestAAMSessionTagsCorrelateAcrossBatchesWhenMetadataArrivesFirst(t *testing.T) {
	groups := identity.GroupEvents([]types.CloudTrailRecord{aamAssumeRoleEvent()})
	_, observed := resolveGroups(groups, nil)
	pk := "creation#" + aamPrincipalID + "#" + aamEventTime
	observedLink := observed[pk]
	if observedLink == nil {
		t.Fatalf("creation link %q was not registered", pk)
	}
	stored := map[string]*link{
		pk: linkFromRecord(pk, &types.DynamoDBIdentityLink{
			PK:          pk,
			SessionTags: observedLink.sessionTags,
		}),
	}

	sessions, err := aggregateForTest([]types.CloudTrailRecord{aamDownstreamEvent()}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}
	assertAAMSessionTags(t, sessions)
}

func TestAAMSessionTagsTargetExistingSessionWhenMetadataArrivesSecond(t *testing.T) {
	pk := "creation#" + aamPrincipalID + "#" + aamEventTime
	stored := map[string]*link{
		pk: linkFromRecord(pk, &types.DynamoDBIdentityLink{
			PK:                pk,
			TargetSessionRefs: []string{aamSessionRef()},
		}),
	}

	metadataGroups := identity.GroupEvents([]types.CloudTrailRecord{aamAssumeRoleEvent()})
	_, links := resolveGroups(metadataGroups, stored)
	updates := collectLateSessionTagUpdates(links, map[string]*types.DynamoDBSession{})
	if len(updates) != 1 {
		t.Fatalf("got %d late updates, want 1: %v", len(updates), updates)
	}
	if got := updates[aamSessionRef()]; !reflect.DeepEqual(got, aamTags) {
		t.Fatalf("late update for %q = %v, want %v", aamSessionRef(), got, aamTags)
	}
}

func TestAAMTagsPropagateToDerivedLoginSession(t *testing.T) {
	grant, vended := aamLoginEvents()

	sessions, err := processForTest([]types.CloudTrailRecord{
		aamAssumeRoleEvent(), aamDownstreamEvent(), grant, vended,
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}
	assertAAMLoginTags(t, sessions)
}

func TestStoredAAMTagsPropagateToDerivedLoginSession(t *testing.T) {
	pk := "creation#" + aamPrincipalID + "#" + aamEventTime
	stored := map[string]*link{
		pk: linkFromRecord(pk, &types.DynamoDBIdentityLink{
			PK:          pk,
			SessionTags: aamTags,
		}),
	}
	grant, vended := aamLoginEvents()
	// Force the vended credentials through the login# identity link. The
	// metadata-only creation# record must not shadow that usable identity link.
	vended.UserIdentity.OnBehalfOf = nil
	sessions, err := aggregateForTest([]types.CloudTrailRecord{
		aamDownstreamEvent(), grant, vended,
	}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}
	assertAAMLoginTags(t, sessions)
}

func aamLoginEvents() (types.CloudTrailRecord, types.CloudTrailRecord) {
	grant := types.CloudTrailRecord{
		EventID:      "00000000-0000-4000-8000-000000000203",
		EventTime:    "2026-08-21T21:06:00Z",
		EventName:    "CreateOAuth2Token",
		EventSource:  "signin.amazonaws.com",
		UserAgent:    "aws-cli/2.34.30 md/command#login",
		UserIdentity: aamIdentity(true, ""),
	}
	vended := types.CloudTrailRecord{
		EventID:      "00000000-0000-4000-8000-000000000204",
		EventTime:    "2026-08-21T21:06:10Z",
		EventName:    "GetCallerIdentity",
		EventSource:  "sts.amazonaws.com",
		UserAgent:    "aws-cli/2.34.30 md/command#sts.get-caller-identity",
		UserIdentity: aamIdentity(false, "ASIAAAMLOGINKEY0001"),
	}
	return grant, vended
}

func assertAAMLoginTags(t *testing.T, sessions map[string]*types.DynamoDBSession) {
	t.Helper()
	loginRef := identity.SessionRef(
		identity.IdentityCenterPersonKey(aamStoreARN, aamUserID),
		identity.SessionSK("key#ASIAAAMLOGINKEY0001", aamRoleID),
	)
	login := sessions[loginRef]
	if login == nil {
		t.Fatalf("LOGIN session %q not found; keys: %v", loginRef, sessionKeys(sessions))
	}
	if login.SessionType != SessionTypeLogin {
		t.Errorf("SessionType = %q, want %q", login.SessionType, SessionTypeLogin)
	}
	if login.LoginGrantedBySession != aamSessionRef() {
		t.Errorf("LoginGrantedBySession = %q, want %q", login.LoginGrantedBySession, aamSessionRef())
	}
	if !reflect.DeepEqual(login.SessionTags, aamTags) {
		t.Errorf("LOGIN SessionTags = %v, want inherited %v", login.SessionTags, aamTags)
	}
}

func TestLateAAMMetadataTargetsConsoleAndDerivedLoginSessions(t *testing.T) {
	pk := "creation#" + aamPrincipalID + "#" + aamEventTime
	loginRef := identity.SessionRef(
		identity.IdentityCenterPersonKey(aamStoreARN, aamUserID),
		identity.SessionSK("key#ASIAAAMLOGINKEY0001", aamRoleID),
	)
	stored := map[string]*link{
		pk: linkFromRecord(pk, &types.DynamoDBIdentityLink{
			PK:                pk,
			TargetSessionRefs: []string{aamSessionRef(), loginRef},
		}),
	}
	groups := identity.GroupEvents([]types.CloudTrailRecord{aamAssumeRoleEvent()})
	_, links := resolveGroups(groups, stored)
	updates := collectLateSessionTagUpdates(links, map[string]*types.DynamoDBSession{})
	if got := updates[aamSessionRef()]; !reflect.DeepEqual(got, aamTags) {
		t.Errorf("late parent update = %v, want %v", got, aamTags)
	}
	if got := updates[loginRef]; !reflect.DeepEqual(got, aamTags) {
		t.Errorf("late login update = %v, want %v", got, aamTags)
	}
}

func TestOnlyAccountAccessServiceAssumeRoleRegistersAAMMetadata(t *testing.T) {
	event := aamAssumeRoleEvent()
	event.UserIdentity.InvokedBy = "cloudformation.amazonaws.com"
	if IsAAMAssumeRole(event) {
		t.Fatal("CloudFormation AssumeRole was classified as AAM")
	}
	links := make(map[string]*link)
	registerCreationMetadata(links, event)
	if len(links) != 0 {
		t.Fatalf("registered AAM links for another AWS service: %v", links)
	}
}
