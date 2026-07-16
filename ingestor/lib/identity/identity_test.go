package identity

import (
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const (
	storeARN      = "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f"
	otherStoreARN = "arn:aws:identitystore::999988887777:identitystore/d-1234567890"
	aliceUserID   = "94482488-3041-7098-e2a1-4d3c9c7e0b21"
)

// ssoEvent builds an AssumedRole event for an Identity Center role session.
// onBehalfOf is attached only when withOBO is true (C1: per-service, not per-session).
func ssoEvent(accessKeyID, sessionName string, withOBO bool) types.CloudTrailRecord {
	e := types.CloudTrailRecord{
		EventID:   "evt-" + accessKeyID + "-" + sessionName,
		EventTime: "2026-07-15T10:00:00Z",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAUB266OVZCWROZTVQR:" + sessionName,
			ARN:         "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + sessionName,
			AccountID:   "278835131762",
			AccessKeyID: accessKeyID,
		},
	}
	if withOBO {
		e.UserIdentity.OnBehalfOf = &types.OnBehalfOf{UserID: aliceUserID, IdentityStoreARN: storeARN}
	}
	return e
}

func TestCredentialGroupKey(t *testing.T) {
	tests := []struct {
		name  string
		event types.CloudTrailRecord
		want  string
	}{
		{
			name:  "access key wins",
			event: ssoEvent("ASIAEXAMPLE1", "alice@example.com", true),
			want:  "ak#ASIAEXAMPLE1",
		},
		{
			name: "no access key falls back to roleID + creationDate",
			event: func() types.CloudTrailRecord {
				e := ssoEvent("", "alice@example.com", false)
				e.UserIdentity.SessionContext = &types.SessionContext{}
				e.UserIdentity.SessionContext.Attributes.CreationDate = "2026-07-15T09:58:00Z"
				return e
			}(),
			want: "rc#AROAUB266OVZCWROZTVQR#2026-07-15T09:58:00Z",
		},
		{
			name: "creationDate normalized to RFC3339",
			event: func() types.CloudTrailRecord {
				e := ssoEvent("", "alice@example.com", false)
				e.UserIdentity.SessionContext = &types.SessionContext{}
				e.UserIdentity.SessionContext.Attributes.CreationDate = "2026-07-15 09:58:00.000"
				return e
			}(),
			want: "rc#AROAUB266OVZCWROZTVQR#2026-07-15T09:58:00Z",
		},
		{
			name: "no credential falls back to eventID",
			event: types.CloudTrailRecord{
				EventID:      "aaaa-bbbb",
				UserIdentity: types.UserIdentity{Type: "AWSService"},
			},
			want: "ev#aaaa-bbbb",
		},
		{
			name:  "nothing groupable",
			event: types.CloudTrailRecord{UserIdentity: types.UserIdentity{Type: "AWSService"}},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CredentialGroupKey(tt.event); got != tt.want {
				t.Errorf("CredentialGroupKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGroupEventsPartitionsByCredential(t *testing.T) {
	events := []types.CloudTrailRecord{
		ssoEvent("ASIAKEY1", "alice@example.com", true),
		ssoEvent("ASIAKEY2", "alice@example.com", false), // refresh: new key, same human
		ssoEvent("ASIAKEY1", "alice@example.com", false),
		{UserIdentity: types.UserIdentity{Type: "AWSService"}}, // ungroupable
		{UserIdentity: types.UserIdentity{Type: "AWSService"}}, // ungroupable — must not merge with previous
	}

	groups := GroupEvents(events)
	if len(groups) != 4 {
		t.Fatalf("got %d groups, want 4 (2 access keys + 2 singleton ungroupables)", len(groups))
	}
	if groups[0].Key != "ak#ASIAKEY1" || len(groups[0].Events) != 2 {
		t.Errorf("group 0 = %q with %d events, want ak#ASIAKEY1 with 2", groups[0].Key, len(groups[0].Events))
	}
	if groups[1].Key != "ak#ASIAKEY2" || len(groups[1].Events) != 1 {
		t.Errorf("group 1 = %q with %d events, want ak#ASIAKEY2 with 1", groups[1].Key, len(groups[1].Events))
	}
	for i := 2; i < 4; i++ {
		if groups[i].Key != "" || len(groups[i].Events) != 1 {
			t.Errorf("group %d = %q with %d events, want singleton with empty key", i, groups[i].Key, len(groups[i].Events))
		}
	}
}

// §8.1(4) C1: a credential group where only some events carry onBehalfOf resolves
// wholly at tier 1 — none of the events leak to the tier-3 email keyspace.
func TestResolveGroupMixedOnBehalfOfResolvesTier1(t *testing.T) {
	var events []types.CloudTrailRecord
	for i := range 5 {
		events = append(events, ssoEvent("ASIASHARED", "alice@example.com", i < 3))
	}
	groups := GroupEvents(events)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}

	person, ok := ResolveGroup(groups[0], nil)
	if !ok {
		t.Fatal("group did not resolve")
	}
	if person.Tier != TierIdentityCenter {
		t.Errorf("Tier = %d, want %d (tier 1)", person.Tier, TierIdentityCenter)
	}
	if want := IdentityCenterPersonKey(storeARN, aliceUserID); person.Key != want {
		t.Errorf("Key = %q, want %q", person.Key, want)
	}
}

// §8.1(1), identity half: a credential refresh mints a new access key, so the events
// land in different credential groups — but both groups resolve to the same person.
func TestCredentialRefreshResolvesToSamePerson(t *testing.T) {
	groups := GroupEvents([]types.CloudTrailRecord{
		ssoEvent("ASIABEFORE", "alice@example.com", true),
		ssoEvent("ASIAAFTER", "alice@example.com", true),
	})
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	p1, ok1 := ResolveGroup(groups[0], nil)
	p2, ok2 := ResolveGroup(groups[1], nil)
	if !ok1 || !ok2 {
		t.Fatal("groups did not both resolve")
	}
	if p1.Key != p2.Key {
		t.Errorf("person keys differ across refresh: %q vs %q", p1.Key, p2.Key)
	}
}

// §8.1(5) C1 cross-batch: a group with no onBehalfOf resolves at tier 2 through the
// injected link resolver (cred# link written by the batch that saw onBehalfOf).
func TestResolveGroupTier2ViaLink(t *testing.T) {
	group := GroupEvents([]types.CloudTrailRecord{ssoEvent("ASIALINKED", "alice@example.com", false)})[0]

	linkedKey := IdentityCenterPersonKey(storeARN, aliceUserID)
	links := func(g Group) (string, bool) {
		if g.Key == "ak#ASIALINKED" {
			return linkedKey, true
		}
		return "", false
	}

	person, ok := ResolveGroup(group, links)
	if !ok {
		t.Fatal("group did not resolve")
	}
	if person.Tier != TierLink {
		t.Errorf("Tier = %d, want %d (tier 2)", person.Tier, TierLink)
	}
	if person.Key != linkedKey {
		t.Errorf("Key = %q, want %q", person.Key, linkedKey)
	}
}

// §8.1(6): the same userId in two identity stores is two people, never merged —
// tier 1 keys on identityStoreArn#userId, not userId alone.
func TestSameUserIDDifferentIdentityStoreNeverMerges(t *testing.T) {
	a := ssoEvent("ASIASTOREA", "alice@example.com", true)
	b := ssoEvent("ASIASTOREB", "alice@example.com", true)
	b.UserIdentity.OnBehalfOf = &types.OnBehalfOf{UserID: aliceUserID, IdentityStoreARN: otherStoreARN}

	pa, _ := ResolveGroup(GroupEvents([]types.CloudTrailRecord{a})[0], nil)
	pb, _ := ResolveGroup(GroupEvents([]types.CloudTrailRecord{b})[0], nil)
	if pa.Key == pb.Key {
		t.Errorf("same userId in different identity stores merged: %q", pa.Key)
	}
}

// §8.1(7): direct SAML federation — role session named with an email, no onBehalfOf —
// resolves at tier 3 with the email lowercased.
func TestResolveGroupTier3SAMLEmail(t *testing.T) {
	e := types.CloudTrailRecord{
		EventID: "evt-saml",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAEXAMPLESAML:Alice@Example.COM",
			ARN:         "arn:aws:sts::278835131762:assumed-role/OktaAdmin/Alice@Example.COM",
			AccessKeyID: "ASIASAML",
		},
	}
	person, ok := ResolveGroup(GroupEvents([]types.CloudTrailRecord{e})[0], nil)
	if !ok {
		t.Fatal("group did not resolve")
	}
	if person.Tier != TierEmail {
		t.Errorf("Tier = %d, want %d (tier 3)", person.Tier, TierEmail)
	}
	if want := "email#alice@example.com"; person.Key != want {
		t.Errorf("Key = %q, want %q", person.Key, want)
	}
}

// §8.1(8): IAM user and root events resolve at tiers 4 and 5.
func TestResolveGroupTier4IAMUser(t *testing.T) {
	e := types.CloudTrailRecord{
		EventID: "evt-iamuser",
		UserIdentity: types.UserIdentity{
			Type:        "IAMUser",
			PrincipalID: "AIDAEXAMPLE",
			ARN:         "arn:aws:iam::278835131762:user/deploy-bot",
			AccountID:   "278835131762",
			AccessKeyID: "AKIAEXAMPLE",
			UserName:    "deploy-bot",
		},
	}
	person, ok := ResolveGroup(GroupEvents([]types.CloudTrailRecord{e})[0], nil)
	if !ok {
		t.Fatal("group did not resolve")
	}
	if person.Tier != TierIAMUser {
		t.Errorf("Tier = %d, want %d (tier 4)", person.Tier, TierIAMUser)
	}
	if want := "iamuser#arn:aws:iam::278835131762:user/deploy-bot"; person.Key != want {
		t.Errorf("Key = %q, want %q", person.Key, want)
	}
}

func TestResolveGroupTier5Root(t *testing.T) {
	e := types.CloudTrailRecord{
		EventID: "evt-root",
		UserIdentity: types.UserIdentity{
			Type:        "Root",
			PrincipalID: "278835131762",
			ARN:         "arn:aws:iam::278835131762:root",
			AccountID:   "278835131762",
		},
	}
	person, ok := ResolveGroup(GroupEvents([]types.CloudTrailRecord{e})[0], nil)
	if !ok {
		t.Fatal("group did not resolve")
	}
	if person.Tier != TierRoot {
		t.Errorf("Tier = %d, want %d (tier 5)", person.Tier, TierRoot)
	}
	if want := "root#278835131762"; person.Key != want {
		t.Errorf("Key = %q, want %q", person.Key, want)
	}
}

// §8.1(9): service-internal traffic matches no tier — no person, no session.
func TestResolveGroupNoTierNoPerson(t *testing.T) {
	e := types.CloudTrailRecord{
		EventID: "evt-svc",
		UserIdentity: types.UserIdentity{
			Type:        "AWSService",
			PrincipalID: "config.amazonaws.com",
		},
	}
	if person, ok := ResolveGroup(GroupEvents([]types.CloudTrailRecord{e})[0], nil); ok {
		t.Errorf("service-internal group resolved to %+v, want no person", person)
	}
}

// Tier order: tier 1 wins even when a tier-3 email is also present in the group.
func TestTier1BeatsTier3(t *testing.T) {
	person, ok := ResolveGroup(GroupEvents([]types.CloudTrailRecord{
		ssoEvent("ASIAORDER", "alice@example.com", true),
	})[0], nil)
	if !ok || person.Tier != TierIdentityCenter {
		t.Errorf("got tier %d (ok=%v), want tier %d", person.Tier, ok, TierIdentityCenter)
	}
}

// Disjoint prefixes: one human seen through every tier yields keys in distinct
// keyspaces — accidental cross-tier merges are impossible by construction.
func TestPersonKeyPrefixesDisjoint(t *testing.T) {
	keys := []string{
		IdentityCenterPersonKey(storeARN, aliceUserID),
		EmailPersonKey("alice@example.com"),
		IAMUserPersonKey("arn:aws:iam::278835131762:user/alice"),
		RootPersonKey("278835131762"),
	}
	prefixes := map[string]bool{}
	for _, k := range keys {
		p := k[:strings.Index(k, "#")+1]
		if prefixes[p] {
			t.Errorf("duplicate keyspace prefix %q", p)
		}
		prefixes[p] = true
	}
	want := []string{"idc#", "email#", "iamuser#", "root#"}
	for _, p := range want {
		if !prefixes[p] {
			t.Errorf("missing keyspace prefix %q, have %v", p, prefixes)
		}
	}
}
