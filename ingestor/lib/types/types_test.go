package types

import (
	"encoding/json"
	"testing"
)

// TestUserIdentityStableFieldsUnmarshal proves the struct tags added for the stable
// cross-refresh identity fields are correct, so encoding/json no longer silently drops
// onBehalfOf, sourceIdentity, and credentialId from userIdentity.
func TestUserIdentityStableFieldsUnmarshal(t *testing.T) {
	// Shapes taken from AWS CloudTrail userIdentity docs: onBehalfOf carries an Identity
	// Center userId + identityStoreArn (arn:aws:identitystore::...:identitystore/d-...),
	// sourceIdentity is the string set at assume-role time, and credentialId is the stable
	// credential handle.
	blob := []byte(`{
		"type": "AssumedRole",
		"principalId": "AROAUB266OVZCWROZTVQR:alex@engseclabs.com",
		"arn": "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/alex@engseclabs.com",
		"accountId": "278835131762",
		"accessKeyId": "ASIAUB266OVZINNJCXNU",
		"onBehalfOf": {
			"userId": "94482488-3041-7098-e2a1-4d3c9c7e0b21",
			"identityStoreArn": "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f"
		},
		"sourceIdentity": "alex@engseclabs.com",
		"credentialId": "EXAMPLEcredentialId1234567890abcdef"
	}`)

	var ui UserIdentity
	if err := json.Unmarshal(blob, &ui); err != nil {
		t.Fatalf("unmarshal userIdentity: %v", err)
	}

	if ui.OnBehalfOf == nil {
		t.Fatal("OnBehalfOf is nil; onBehalfOf was dropped during unmarshal")
	}
	if got, want := ui.OnBehalfOf.UserID, "94482488-3041-7098-e2a1-4d3c9c7e0b21"; got != want {
		t.Errorf("OnBehalfOf.UserID = %q, want %q", got, want)
	}
	if got, want := ui.OnBehalfOf.IdentityStoreARN, "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f"; got != want {
		t.Errorf("OnBehalfOf.IdentityStoreARN = %q, want %q", got, want)
	}
	if got, want := ui.SourceIdentity, "alex@engseclabs.com"; got != want {
		t.Errorf("SourceIdentity = %q, want %q", got, want)
	}
	if got, want := ui.CredentialID, "EXAMPLEcredentialId1234567890abcdef"; got != want {
		t.Errorf("CredentialID = %q, want %q", got, want)
	}
}

// TestUserIdentityStableFieldsAbsent confirms absence is distinguishable: OnBehalfOf is a
// pointer, so a userIdentity without the field unmarshals to nil rather than an empty object.
func TestUserIdentityStableFieldsAbsent(t *testing.T) {
	blob := []byte(`{
		"type": "AssumedRole",
		"principalId": "AROAUB266OVZCWROZTVQR:alex@engseclabs.com",
		"arn": "arn:aws:sts::278835131762:assumed-role/Role/alex@engseclabs.com"
	}`)

	var ui UserIdentity
	if err := json.Unmarshal(blob, &ui); err != nil {
		t.Fatalf("unmarshal userIdentity: %v", err)
	}
	if ui.OnBehalfOf != nil {
		t.Errorf("OnBehalfOf = %+v, want nil when onBehalfOf absent", ui.OnBehalfOf)
	}
	if ui.SourceIdentity != "" {
		t.Errorf("SourceIdentity = %q, want empty when absent", ui.SourceIdentity)
	}
	if ui.CredentialID != "" {
		t.Errorf("CredentialID = %q, want empty when absent", ui.CredentialID)
	}
}
