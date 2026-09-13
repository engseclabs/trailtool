package aggregator

import (
	"reflect"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const (
	samlEventTime     = "2026-08-20T02:56:50Z"
	samlRoleID        = "AROAUB266OVZCWROZTVQR"
	samlSessionName   = "alex@engseclabs.com"
	samlPrincipalID   = samlRoleID + ":" + samlSessionName
	samlRoleARN       = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
	samlStoreARN      = "arn:aws:identitystore::843363563907:identitystore/d-9a675246c6"
	samlUserID        = "11fb6570-3051-707e-a14f-d5a0d1f455fe"
	samlIssuedKey     = "ASIAISSUEDKEY000001"
	samlDownstreamKey = "ASIADOWNSTREAM00001"
)

var samlTags = map[string]string{
	"email":      "alex@engseclabs.com",
	"department": "security",
}

// samlFederationEvent models the relevant fields from a real Identity Center
// AssumeRoleWithSAML CloudTrail event. The response key deliberately differs
// from the key on samlDownstreamEvent, matching the observed AWS behavior.
func samlFederationEvent() types.CloudTrailRecord {
	return types.CloudTrailRecord{
		EventID:     "b5a89fbd-edec-474c-b75d-36bd3c823380",
		EventTime:   samlEventTime,
		EventName:   "AssumeRoleWithSAML",
		EventSource: "sts.amazonaws.com",
		AwsRegion:   "us-east-2",
		UserAgent:   "aws-sdk-java/2.46.18",
		UserIdentity: types.UserIdentity{
			Type:        "SAMLUser",
			PrincipalID: "4xZXicN6TGyAaMwC5tBBs8KGuSg=:" + samlSessionName,
			UserName:    samlSessionName,
		},
		RequestParameters: map[string]interface{}{
			"roleArn":         samlRoleARN,
			"roleSessionName": samlSessionName,
			"principalTags": map[string]interface{}{
				"email":      samlTags["email"],
				"department": samlTags["department"],
			},
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId": samlIssuedKey,
			},
			"assumedRoleUser": map[string]interface{}{
				"assumedRoleId": samlPrincipalID,
				"arn":           "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + samlSessionName,
			},
		},
	}
}

func samlDownstreamEvent() types.CloudTrailRecord {
	sc := makeSessionContext(samlEventTime, samlRoleARN)
	sc.Attributes.SessionCredentialFromConsole = "true"
	return types.CloudTrailRecord{
		EventID:     "b5d7aa77-9644-4dac-ac52-a894c1028f10",
		EventTime:   "2026-08-20T02:56:51Z",
		EventName:   "AttachRolePolicy",
		EventSource: "iam.amazonaws.com",
		AwsRegion:   "us-east-1",
		UserAgent:   "AWS Internal",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    samlPrincipalID,
			ARN:            "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + samlSessionName,
			AccountID:      "278835131762",
			AccessKeyID:    samlDownstreamKey,
			SessionContext: sc,
			OnBehalfOf: &types.OnBehalfOf{
				UserID:           samlUserID,
				IdentityStoreARN: samlStoreARN,
			},
		},
	}
}

func samlSessionRef() string {
	personKey := identity.IdentityCenterPersonKey(samlStoreARN, samlUserID)
	return identity.SessionRef(personKey, identity.SessionSK("web#"+samlRoleID+"#"+samlEventTime, samlRoleID))
}

func assertSAMLSessionTags(t *testing.T, sessions map[string]*types.DynamoDBSession) {
	t.Helper()
	sess := sessions[samlSessionRef()]
	if sess == nil {
		t.Fatalf("SAML session %q not found; keys: %v", samlSessionRef(), sessionKeys(sessions))
	}
	if !reflect.DeepEqual(sess.SessionTags, samlTags) {
		t.Errorf("SessionTags = %v, want %v", sess.SessionTags, samlTags)
	}
	if sess.EventsCount != 1 {
		t.Errorf("EventsCount = %d, want 1 (federation metadata must not count as activity)", sess.EventsCount)
	}
	if sess.AssumedFromSession != "" {
		t.Errorf("AssumedFromSession = %q, want empty (SAML federation is not role chaining)", sess.AssumedFromSession)
	}
}

func TestSAMLPrincipalTagsCorrelateInBatchRegardlessOfEventOrder(t *testing.T) {
	for _, tt := range []struct {
		name   string
		events []types.CloudTrailRecord
	}{
		{name: "federation metadata first", events: []types.CloudTrailRecord{samlFederationEvent(), samlDownstreamEvent()}},
		{name: "downstream activity first", events: []types.CloudTrailRecord{samlDownstreamEvent(), samlFederationEvent()}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := processForTest(tt.events)
			if err != nil {
				t.Fatalf("processForTest() error: %v", err)
			}
			if len(sessions) != 1 {
				t.Fatalf("got %d sessions, want 1; keys: %v", len(sessions), sessionKeys(sessions))
			}
			assertSAMLSessionTags(t, sessions)
		})
	}
}

func TestSAMLPrincipalTagsDoNotRequireFederationEventIdentityResolution(t *testing.T) {
	federation := samlFederationEvent()
	federation.UserIdentity.PrincipalID = "4xZXicN6TGyAaMwC5tBBs8KGuSg=:opaque-name-id"
	federation.UserIdentity.UserName = "opaque-name-id"

	sessions, err := processForTest([]types.CloudTrailRecord{federation, samlDownstreamEvent()})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}
	assertSAMLSessionTags(t, sessions)
}

func TestSAMLPrincipalTagsCorrelateAcrossBatchesWhenMetadataArrivesFirst(t *testing.T) {
	groups := identity.GroupEvents([]types.CloudTrailRecord{samlFederationEvent()})
	_, observed := resolveGroups(groups, nil)
	pk := "creation#" + samlPrincipalID + "#" + samlEventTime
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

	sessions, err := aggregateForTest([]types.CloudTrailRecord{samlDownstreamEvent()}, stored)
	if err != nil {
		t.Fatalf("aggregateForTest() error: %v", err)
	}
	assertSAMLSessionTags(t, sessions)
}

func TestSAMLPrincipalTagsTargetExistingSessionWhenMetadataArrivesSecond(t *testing.T) {
	pk := "creation#" + samlPrincipalID + "#" + samlEventTime
	stored := map[string]*link{
		pk: linkFromRecord(pk, &types.DynamoDBIdentityLink{
			PK:                pk,
			TargetSessionRefs: []string{samlSessionRef()},
		}),
	}

	federationGroups := identity.GroupEvents([]types.CloudTrailRecord{samlFederationEvent()})
	_, links := resolveGroups(federationGroups, stored)
	updates := collectLateSessionTagUpdates(links, map[string]*types.DynamoDBSession{})

	if len(updates) != 1 {
		t.Fatalf("got %d late updates, want 1: %v", len(updates), updates)
	}
	if got := updates[samlSessionRef()]; !reflect.DeepEqual(got, samlTags) {
		t.Fatalf("late update for %q = %v, want %v", samlSessionRef(), got, samlTags)
	}
}

func TestSAMLPrincipalTagsTargetSignInAnchoredSession(t *testing.T) {
	activity := samlDownstreamEvent()
	const signInSessionARN = "arn:aws:signin:::session/saml-console"
	activity.UserIdentity.SessionContext.SignInSessionArn = signInSessionARN
	personKey := identity.IdentityCenterPersonKey(samlStoreARN, samlUserID)
	targetRef := identity.SessionRef(personKey, identity.SessionSK("sis#"+signInSessionARN, samlRoleID))
	pk := "creation#" + samlPrincipalID + "#" + samlEventTime
	links := map[string]*link{}
	registerCreationTarget(links, activity, targetRef)

	metadataGroups := identity.GroupEvents([]types.CloudTrailRecord{samlFederationEvent()})
	_, links = resolveGroups(metadataGroups, links)
	updates := collectLateSessionTagUpdates(links, map[string]*types.DynamoDBSession{})
	if got := updates[targetRef]; !reflect.DeepEqual(got, samlTags) {
		t.Fatalf("late sign-in update for %q = %v, want %v", targetRef, got, samlTags)
	}
	if links[pk] == nil || len(links[pk].targetSessionRefs) != 1 {
		t.Fatalf("creation target was not retained: %#v", links[pk])
	}
}
