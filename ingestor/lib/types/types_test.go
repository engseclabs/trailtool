package types

import (
	"encoding/json"
	"testing"
)

// TestCloudTrailRecordIdentityFieldsUnmarshal proves the struct tags for the 1.0
// identity fields are correct, so encoding/json no longer silently drops them:
// eventID/awsRegion/recipientAccountId on the record, onBehalfOf/userName/invokedBy/
// credentialId on userIdentity, and sourceIdentity on sessionContext.
func TestCloudTrailRecordIdentityFieldsUnmarshal(t *testing.T) {
	// Shapes taken from the AWS CloudTrail userIdentity element reference: onBehalfOf
	// carries an Identity Center userId + identityStoreArn, sourceIdentity lives in
	// sessionContext, and credentialId is the bearer-token credential handle.
	blob := []byte(`{
		"eventVersion": "1.11",
		"eventID": "b1b2c3d4-1111-2222-3333-444455556666",
		"eventTime": "2026-07-15T10:00:00Z",
		"eventName": "ListBuckets",
		"eventSource": "s3.amazonaws.com",
		"awsRegion": "us-east-1",
		"recipientAccountId": "278835131762",
		"userIdentity": {
			"type": "AssumedRole",
			"principalId": "AROAUB266OVZCWROZTVQR:alex@engseclabs.com",
			"arn": "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/alex@engseclabs.com",
			"accountId": "278835131762",
			"accessKeyId": "ASIAUB266OVZINNJCXNU",
			"userName": "alex",
			"invokedBy": "cloudformation.amazonaws.com",
			"credentialId": "EXAMPLEcredentialId1234567890abcdef",
			"onBehalfOf": {
				"userId": "94482488-3041-7098-e2a1-4d3c9c7e0b21",
				"identityStoreArn": "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f"
			},
			"sessionContext": {
				"attributes": {
					"creationDate": "2026-07-15T09:58:00Z",
					"mfaAuthenticated": "false"
				},
				"sourceIdentity": "alex@engseclabs.com"
			}
		}
	}`)

	var rec CloudTrailRecord
	if err := json.Unmarshal(blob, &rec); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}

	if got, want := rec.EventID, "b1b2c3d4-1111-2222-3333-444455556666"; got != want {
		t.Errorf("EventID = %q, want %q", got, want)
	}
	if got, want := rec.AwsRegion, "us-east-1"; got != want {
		t.Errorf("AwsRegion = %q, want %q", got, want)
	}
	if got, want := rec.RecipientAccountID, "278835131762"; got != want {
		t.Errorf("RecipientAccountID = %q, want %q", got, want)
	}

	ui := rec.UserIdentity
	if ui.OnBehalfOf == nil {
		t.Fatal("OnBehalfOf is nil; onBehalfOf was dropped during unmarshal")
	}
	if got, want := ui.OnBehalfOf.UserID, "94482488-3041-7098-e2a1-4d3c9c7e0b21"; got != want {
		t.Errorf("OnBehalfOf.UserID = %q, want %q", got, want)
	}
	if got, want := ui.OnBehalfOf.IdentityStoreARN, "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f"; got != want {
		t.Errorf("OnBehalfOf.IdentityStoreARN = %q, want %q", got, want)
	}
	if got, want := ui.UserName, "alex"; got != want {
		t.Errorf("UserName = %q, want %q", got, want)
	}
	if got, want := ui.InvokedBy, "cloudformation.amazonaws.com"; got != want {
		t.Errorf("InvokedBy = %q, want %q", got, want)
	}
	if got, want := ui.CredentialID, "EXAMPLEcredentialId1234567890abcdef"; got != want {
		t.Errorf("CredentialID = %q, want %q", got, want)
	}
	if ui.SessionContext == nil {
		t.Fatal("SessionContext is nil")
	}
	if got, want := ui.SessionContext.SourceIdentity, "alex@engseclabs.com"; got != want {
		t.Errorf("SessionContext.SourceIdentity = %q, want %q", got, want)
	}
}

// TestUserIdentityIdentityFieldsAbsent confirms absence is distinguishable: OnBehalfOf
// is a pointer, so a userIdentity without the element unmarshals to nil rather than an
// empty struct, and the scalar fields stay empty.
func TestUserIdentityIdentityFieldsAbsent(t *testing.T) {
	blob := []byte(`{
		"type": "AssumedRole",
		"principalId": "AROAUB266OVZCWROZTVQR:alex@engseclabs.com",
		"arn": "arn:aws:sts::278835131762:assumed-role/Role/alex@engseclabs.com",
		"sessionContext": {
			"attributes": {"creationDate": "2026-07-15T09:58:00Z"}
		}
	}`)

	var ui UserIdentity
	if err := json.Unmarshal(blob, &ui); err != nil {
		t.Fatalf("unmarshal userIdentity: %v", err)
	}
	if ui.OnBehalfOf != nil {
		t.Errorf("OnBehalfOf = %+v, want nil when onBehalfOf absent", ui.OnBehalfOf)
	}
	if ui.UserName != "" {
		t.Errorf("UserName = %q, want empty when absent", ui.UserName)
	}
	if ui.InvokedBy != "" {
		t.Errorf("InvokedBy = %q, want empty when absent", ui.InvokedBy)
	}
	if ui.CredentialID != "" {
		t.Errorf("CredentialID = %q, want empty when absent", ui.CredentialID)
	}
	if ui.SessionContext.SourceIdentity != "" {
		t.Errorf("SessionContext.SourceIdentity = %q, want empty when absent", ui.SessionContext.SourceIdentity)
	}
}
