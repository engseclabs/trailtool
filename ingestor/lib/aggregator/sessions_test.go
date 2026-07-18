// Session-identity scenarios (§8.1): anchor cascade behaviour, windowed
// fallback, service-driven events, and batch hygiene.
package aggregator

import (
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

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

// TestServiceFanOutJoinsOriginatingSession models the observed sandbox
// failure: CloudFormation deploying a stack fans out hundreds of calls with
// the human's credentials (invokedBy set), each under a FRESH per-request
// access key but sharing the originating credential's creationDate. Those
// events must join the human's key# session as service-driven counts — not
// shatter into one key# session per request key.
func TestServiceFanOutJoinsOriginatingSession(t *testing.T) {
	const (
		email        = "alex@engseclabs.com"
		roleID       = "AROAUB266OVZCWROZTVQR"
		roleARN      = "arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_78658cb1063311db"
		humanKey     = "ASIAUB266OVZCKEQQ6MH"
		creationDate = "2026-07-17T20:43:51Z"
		accountID    = "278835131762"
	)
	principal := roleID + ":" + email
	stsARN := "arn:aws:sts::278835131762:assumed-role/AWSReservedSSO_AdministratorAccess_78658cb1063311db/" + email

	humanEvent := types.CloudTrailRecord{
		EventTime:   "2026-07-17T20:43:52Z",
		EventName:   "CreateStack",
		EventSource: "cloudformation.amazonaws.com",
		UserAgent:   "Boto3/1.42.70",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    principal,
			ARN:            stsARN,
			AccountID:      accountID,
			AccessKeyID:    humanKey,
			SessionContext: makeSessionContext(creationDate, roleARN),
			OnBehalfOf: &types.OnBehalfOf{
				UserID:           "94482488-3041-7098-e2a1-4d3c9c7e0b21",
				IdentityStoreARN: "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f",
			},
		},
	}

	// Fan-out: fresh ASIA key per request, same principal + creationDate.
	newFanOutEvent := func(eventTime, name, requestKey string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: "dynamodb.amazonaws.com",
			UserAgent:   "cloudformation.amazonaws.com",
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    principal,
				ARN:            stsARN,
				AccountID:      accountID,
				AccessKeyID:    requestKey,
				InvokedBy:      "cloudformation.amazonaws.com",
				SessionContext: makeSessionContext(creationDate, roleARN),
				OnBehalfOf: &types.OnBehalfOf{
					UserID:           "94482488-3041-7098-e2a1-4d3c9c7e0b21",
					IdentityStoreARN: "arn:aws:identitystore::278835131762:identitystore/d-9967750e0f",
				},
			},
		}
	}

	// Fan-out events arrive BEFORE the human's own event in the file, as
	// observed — resolution ordering must not depend on file order.
	sessions, err := processForTest([]types.CloudTrailRecord{
		newFanOutEvent("2026-07-17T20:44:01Z", "DescribeTable", "ASIAFANOUT0000000001"),
		newFanOutEvent("2026-07-17T20:44:02Z", "DescribeContinuousBackups", "ASIAFANOUT0000000002"),
		newFanOutEvent("2026-07-17T20:44:03Z", "ListTagsOfResource", "ASIAFANOUT0000000003"),
		humanEvent,
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1 (fan-out must not shatter into per-request sessions); keys: %v",
			len(sessions), sessionKeys(sessions))
	}
	personKey := identity.IdentityCenterPersonKey(
		"arn:aws:identitystore::278835131762:identitystore/d-9967750e0f",
		"94482488-3041-7098-e2a1-4d3c9c7e0b21")
	sess := sessions[ref(personKey, "key#"+humanKey, roleID)]
	if sess == nil {
		t.Fatalf("expected the human's key# session; keys: %v", sessionKeys(sessions))
	}
	if sess.EventsCount != 4 {
		t.Errorf("EventsCount = %d, want 4 (1 human + 3 fan-out)", sess.EventsCount)
	}
	if sess.ServiceDrivenEventCount != 3 {
		t.Errorf("ServiceDrivenEventCount = %d, want 3", sess.ServiceDrivenEventCount)
	}
	if sess.SessionType != SessionTypeCLI {
		t.Errorf("SessionType = %q, want %q", sess.SessionType, SessionTypeCLI)
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
