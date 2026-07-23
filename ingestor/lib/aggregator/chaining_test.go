// Role-chaining attribution: CLI assume-role, console switch-role, and
// session-tag propagation onto chained child sessions.
package aggregator

import (
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// TestChainAttributionCounts verifies programmatic role chaining: the child
// credential is one key# session under the person's own partition with
// assumed_from_session set, and the parent session accumulates chained counters.
func TestChainAttributionCounts(t *testing.T) {
	const (
		parentEmail    = "bob@example.com"
		parentRoleID   = "AROABOBEXAMPLE12345"
		parentRoleARN  = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Viewer_def456"
		assumedRoleARN = "arn:aws:iam::333333333333:role/ReadOnlyRole"
		issuedKey      = "ASIABOBKEY1234567890"
		creationDate   = "2024-02-01T08:00:00Z"
		accountID      = "111111111111"
	)

	assumeRoleEvent := types.CloudTrailRecord{
		EventTime:   "2024-02-01T08:05:00Z",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Viewer_def456/" + parentEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
		},
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		RequestParameters: map[string]interface{}{
			"roleArn":         assumedRoleARN,
			"roleSessionName": "read-session",
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":     issuedKey,
				"secretAccessKey": "secret",
				"sessionToken":    "token",
			},
		},
	}

	newChainedEvent := func(eventTime, name, src string) types.CloudTrailRecord {
		return types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: src,
			UserIdentity: types.UserIdentity{
				Type:        "AssumedRole",
				PrincipalID: "AROAREADONLY:read-session",
				ARN:         "arn:aws:sts::333333333333:assumed-role/ReadOnlyRole/read-session",
				AccountID:   "333333333333",
				AccessKeyID: issuedKey,
			},
			UserAgent: "aws-cli/2.15.0",
		}
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		assumeRoleEvent,
		newChainedEvent("2024-02-01T08:10:00Z", "ListBuckets", "s3.amazonaws.com"),
		newChainedEvent("2024-02-01T08:11:00Z", "DescribeInstances", "ec2.amazonaws.com"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := "email#" + parentEmail
	parentAnchor := "web#" + parentRoleID + "#" + creationDate
	parentRef := ref(personKey, parentAnchor, parentRoleID)
	childRef := ref(personKey, "key#"+issuedKey, "AROAREADONLY")

	parentSess, ok := sessions[parentRef]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", parentRef, sessionKeys(sessions))
	}
	if parentSess.ChainedEventCount != 2 {
		t.Errorf("parent ChainedEventCount = %d, want 2", parentSess.ChainedEventCount)
	}
	if len(parentSess.ChainedRoles) != 1 || parentSess.ChainedRoles[0] != assumedRoleARN {
		t.Errorf("parent ChainedRoles = %v, want [%s]", parentSess.ChainedRoles, assumedRoleARN)
	}
	if len(parentSess.ChainedSessionRefs) != 1 || parentSess.ChainedSessionRefs[0] != childRef {
		t.Errorf("parent ChainedSessionRefs = %v, want [%s]", parentSess.ChainedSessionRefs, childRef)
	}

	childSess, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if childSess.EventsCount != 2 {
		t.Errorf("child EventsCount = %d, want 2", childSess.EventsCount)
	}
	if childSess.PersonKey != personKey {
		t.Errorf("child PersonKey = %q, want %q (chained session lives under the person)", childSess.PersonKey, personKey)
	}
	if childSess.AssumedFromSession != parentRef {
		t.Errorf("child AssumedFromSession = %q, want %q", childSess.AssumedFromSession, parentRef)
	}
	if childSess.AssumedFromRoleARN != parentRoleARN {
		t.Errorf("child AssumedFromRoleARN = %q, want %q", childSess.AssumedFromRoleARN, parentRoleARN)
	}
	if childSess.RoleARN != assumedRoleARN {
		t.Errorf("child RoleARN = %q, want %q", childSess.RoleARN, assumedRoleARN)
	}
	if childSess.SessionType != SessionTypeCLI {
		t.Errorf("child SessionType = %q, want %q", childSess.SessionType, SessionTypeCLI)
	}
}

// TestConsoleRoleSwitchChaining verifies §8.1(13): the console's AssumeRole vends
// a child *console* session — fresh access key per request but one creationDate
// (== the AssumeRole event time). The cascade anchors it web#, and the
// console-variant chain link attributes it to the person with
// assumed_from_session pointing at the parent.
func TestConsoleRoleSwitchChaining(t *testing.T) {
	const (
		parentEmail    = "alice@example.com"
		parentRoleID   = "AROAALICEPARENT12345"
		parentRoleARN  = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		assumedRoleARN = "arn:aws:iam::222222222222:role/RoleChaining1"
		assumedRoleID  = "AROACHAINING000001"
		issuedKey      = "ASIACONSOLEKEY12345"
		creationDate   = "2024-03-01T10:00:00Z"
		switchTime     = "2024-03-01T10:05:00Z" // AssumeRole event time == child creationDate
		accountID      = "111111111111"
		browserUA      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
	)

	assumeRoleEvent := types.CloudTrailRecord{
		EventTime:   switchTime,
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + parentEmail,
			ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc123/" + parentEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
		},
		UserAgent: browserUA,
		RequestParameters: map[string]interface{}{
			"roleArn":         assumedRoleARN,
			"roleSessionName": parentEmail,
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":     issuedKey,
				"secretAccessKey": "secret",
				"sessionToken":    "token",
			},
			"assumedRoleUser": map[string]interface{}{
				"assumedRoleId": assumedRoleID + ":" + parentEmail,
				"arn":           "arn:aws:sts::222222222222:assumed-role/RoleChaining1/" + parentEmail,
			},
		},
	}

	// Child console events: a fresh access key per request, one creationDate.
	newChildEvent := func(eventTime, name, src, requestKey string) types.CloudTrailRecord {
		e := types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: src,
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    assumedRoleID + ":" + parentEmail,
				ARN:            "arn:aws:sts::222222222222:assumed-role/RoleChaining1/" + parentEmail,
				AccountID:      "222222222222",
				AccessKeyID:    requestKey,
				SessionContext: makeSessionContext(switchTime, assumedRoleARN),
			},
			UserAgent: browserUA,
		}
		e.UserIdentity.SessionContext.Attributes.SessionCredentialFromConsole = "true"
		return e
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		assumeRoleEvent,
		newChildEvent("2024-03-01T10:10:00Z", "ListBuckets", "s3.amazonaws.com", "ASIACHILDREQ1"),
		newChildEvent("2024-03-01T10:11:00Z", "DescribeInstances", "ec2.amazonaws.com", "ASIACHILDREQ2"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := "email#" + parentEmail
	parentRef := ref(personKey, "web#"+parentRoleID+"#"+creationDate, parentRoleID)
	childRef := ref(personKey, "web#"+assumedRoleID+"#"+switchTime, assumedRoleID)

	parentSess, ok := sessions[parentRef]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", parentRef, sessionKeys(sessions))
	}
	if parentSess.ChainedEventCount != 2 {
		t.Errorf("parent ChainedEventCount = %d, want 2", parentSess.ChainedEventCount)
	}
	if len(parentSess.ChainedRoles) != 1 || parentSess.ChainedRoles[0] != assumedRoleARN {
		t.Errorf("parent ChainedRoles = %v, want [%s]", parentSess.ChainedRoles, assumedRoleARN)
	}

	childSess, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if childSess.EventsCount != 2 {
		t.Errorf("child EventsCount = %d, want 2 (per-request keys must not split the child)", childSess.EventsCount)
	}
	if childSess.SessionType != SessionTypeWeb {
		t.Errorf("child SessionType = %q, want %q", childSess.SessionType, SessionTypeWeb)
	}
	if childSess.AssumedFromSession != parentRef {
		t.Errorf("child AssumedFromSession = %q, want %q", childSess.AssumedFromSession, parentRef)
	}
	if childSess.RoleARN != assumedRoleARN {
		t.Errorf("child RoleARN = %q, want %q", childSess.RoleARN, assumedRoleARN)
	}
}

// TestConsoleRoleSwitchBackendUA reproduces the real sandbox mis-attribution: the
// console's Switch-Role AssumeRole is emitted by AWS's Switch-Role backend with
// userAgent "AWS Signin, aws-internal/…" and NO sessionCredentialFromConsole
// flag — so isConsoleSessionCredential is false and, unlike
// TestConsoleRoleSwitchChaining (which uses a browser UA), the event does not
// anchor web# by itself. It carries one of the console session's per-request
// access keys and the console session's own creationDate. Without the
// same-session web# continuity fold it splits into a phantom key# session that
// mis-parents the child (child.assumed_from_session points at the phantom, not
// the console session). This asserts the AssumeRole folds into the console
// session and the child is parented to it.
func TestConsoleRoleSwitchBackendUA(t *testing.T) {
	const (
		email          = "alex@engseclabs.com"
		parentRoleID   = "AROAPARENTCONSOLE001"
		parentRoleARN  = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		assumedRoleARN = "arn:aws:iam::111111111111:role/RoleChaining1"
		assumedRoleID  = "AROACHAINING000001"
		consoleKey     = "ASIACONSOLEREQKEY001" // a per-request console credential
		creationDate   = "2026-07-23T19:51:29Z" // the console session's creationDate
		switchTime     = "2026-07-23T19:53:09Z" // AssumeRole time == child creationDate
		accountID      = "111111111111"
		browserUA      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
		backendUA      = "AWS Signin, aws-internal/3 aws-sdk-java/2.20.0"
	)
	principalID := parentRoleID + ":" + email
	parentARN := "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc123/" + email

	// A genuine console click under the console session: browser UA anchors web#
	// and registers the cd-keyed cred continuity link the fold relies on.
	consoleClick := types.CloudTrailRecord{
		EventTime:   "2026-07-23T19:52:00Z",
		EventName:   "GetRole",
		EventSource: "iam.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    principalID,
			ARN:            parentARN,
			AccountID:      accountID,
			AccessKeyID:    "ASIACONSOLEREQKEY000", // a different per-request key
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
		},
		UserAgent: browserUA,
	}
	consoleClick.UserIdentity.SessionContext.Attributes.SessionCredentialFromConsole = "true"

	// The Switch-Role AssumeRole: backend UA, no console flag, its own key, but
	// the console session's principalId + creationDate.
	assumeRoleEvent := types.CloudTrailRecord{
		EventTime:   switchTime,
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    principalID,
			ARN:            parentARN,
			AccountID:      accountID,
			AccessKeyID:    consoleKey,
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
		},
		UserAgent: backendUA,
		RequestParameters: map[string]interface{}{
			"roleArn":         assumedRoleARN,
			"roleSessionName": email,
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":     "ASIACHILDVEND0000001",
				"secretAccessKey": "secret",
				"sessionToken":    "token",
			},
			"assumedRoleUser": map[string]interface{}{
				"assumedRoleId": assumedRoleID + ":" + email,
				"arn":           "arn:aws:sts::111111111111:assumed-role/RoleChaining1/" + email,
			},
		},
	}

	// Child console events: fresh per-request keys, one creationDate == switchTime.
	newChildEvent := func(eventTime, name, src, reqKey string) types.CloudTrailRecord {
		e := types.CloudTrailRecord{
			EventTime:   eventTime,
			EventName:   name,
			EventSource: src,
			UserIdentity: types.UserIdentity{
				Type:           "AssumedRole",
				PrincipalID:    assumedRoleID + ":" + email,
				ARN:            "arn:aws:sts::111111111111:assumed-role/RoleChaining1/" + email,
				AccountID:      accountID,
				AccessKeyID:    reqKey,
				SessionContext: makeSessionContext(switchTime, assumedRoleARN),
			},
			UserAgent: browserUA,
		}
		e.UserIdentity.SessionContext.Attributes.SessionCredentialFromConsole = "true"
		return e
	}

	sessions, err := processForTest([]types.CloudTrailRecord{
		consoleClick,
		assumeRoleEvent,
		newChildEvent("2026-07-23T19:54:00Z", "ListBuckets", "s3.amazonaws.com", "ASIACHILDREQ1"),
		newChildEvent("2026-07-23T19:55:00Z", "DescribeInstances", "ec2.amazonaws.com", "ASIACHILDREQ2"),
	})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := "email#" + email
	consoleRef := ref(personKey, "web#"+parentRoleID+"#"+creationDate, parentRoleID)
	childRef := ref(personKey, "web#"+assumedRoleID+"#"+switchTime, assumedRoleID)

	// The AssumeRole must fold into the console session — no phantom key# session.
	phantomRef := ref(personKey, "key#"+consoleKey, parentRoleID)
	if _, ok := sessions[phantomRef]; ok {
		t.Errorf("phantom key# session %q exists — the Switch-Role AssumeRole split off instead of folding into the console session", phantomRef)
	}

	consoleSess, ok := sessions[consoleRef]
	if !ok {
		t.Fatalf("console session %q not found; keys: %v", consoleRef, sessionKeys(sessions))
	}
	if consoleSess.SessionType != SessionTypeWeb {
		t.Errorf("console SessionType = %q, want %q", consoleSess.SessionType, SessionTypeWeb)
	}
	if consoleSess.ChainedEventCount != 2 {
		t.Errorf("console ChainedEventCount = %d, want 2", consoleSess.ChainedEventCount)
	}
	if len(consoleSess.ChainedSessionRefs) != 1 || consoleSess.ChainedSessionRefs[0] != childRef {
		t.Errorf("console ChainedSessionRefs = %v, want [%s]", consoleSess.ChainedSessionRefs, childRef)
	}

	childSess, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if childSess.AssumedFromSession != consoleRef {
		t.Errorf("child AssumedFromSession = %q, want %q (the real console session, not a phantom key# session)", childSess.AssumedFromSession, consoleRef)
	}
	if childSess.EventsCount != 2 {
		t.Errorf("child EventsCount = %d, want 2", childSess.EventsCount)
	}
}

// TestTaggedAssumeRoleAttribution verifies an AssumeRole carrying session tags
// propagates them to the child session record.
func TestTaggedAssumeRoleAttribution(t *testing.T) {
	const (
		humanEmail    = "alice@example.com"
		parentRoleID  = "AROAALICEPARENT12345"
		parentRoleARN = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"
		agentRoleARN  = "arn:aws:iam::111111111111:role/claude-code-agent"
		issuedKey     = "ASIAAGENTKEY00000001"
		creationDate  = "2026-04-20T14:00:00Z"
		accountID     = "111111111111"
	)

	agentAssumeRoleEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-20T14:30:00Z",
		EventName:   "AssumeRole",
		EventSource: "sts.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:           "AssumedRole",
			PrincipalID:    parentRoleID + ":" + humanEmail,
			ARN:            "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_Admin_abc123/" + humanEmail,
			AccountID:      accountID,
			SessionContext: makeSessionContext(creationDate, parentRoleARN),
		},
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		RequestParameters: map[string]interface{}{
			"roleArn":         agentRoleARN,
			"roleSessionName": "claude-code-deploy-lambda",
			"tags": []interface{}{
				map[string]interface{}{"key": "AgentName", "value": "claude-code"},
				map[string]interface{}{"key": "Task", "value": "deploy-lambda"},
				map[string]interface{}{"key": "HumanSession", "value": humanEmail},
			},
		},
		ResponseElements: map[string]interface{}{
			"credentials": map[string]interface{}{
				"accessKeyId":     issuedKey,
				"secretAccessKey": "secret",
				"sessionToken":    "token",
			},
			"assumedRoleUser": map[string]interface{}{
				"assumedRoleId": "AROAAGENTROLEID12345:claude-code-deploy-lambda",
				"arn":           "arn:aws:sts::111111111111:assumed-role/claude-code-agent/claude-code-deploy-lambda",
			},
		},
	}

	agentEvent := types.CloudTrailRecord{
		EventTime:   "2026-04-20T14:31:00Z",
		EventName:   "UpdateFunctionCode20150331v2",
		EventSource: "lambda.amazonaws.com",
		UserIdentity: types.UserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAAGENTROLEID12345:claude-code-deploy-lambda",
			ARN:         "arn:aws:sts::111111111111:assumed-role/claude-code-agent/claude-code-deploy-lambda",
			AccountID:   accountID,
			AccessKeyID: issuedKey,
		},
		UserAgent: "go-http-client/2.0",
	}

	sessions, err := processForTest([]types.CloudTrailRecord{agentAssumeRoleEvent, agentEvent})
	if err != nil {
		t.Fatalf("processForTest() error: %v", err)
	}

	personKey := "email#" + humanEmail
	childRef := ref(personKey, "key#"+issuedKey, "AROAAGENTROLEID12345")
	childSess, ok := sessions[childRef]
	if !ok {
		t.Fatalf("child session %q not found; keys: %v", childRef, sessionKeys(sessions))
	}
	if childSess.SessionType != SessionTypeCLI {
		t.Errorf("child SessionType = %q, want %q", childSess.SessionType, SessionTypeCLI)
	}
	if childSess.SessionTags["AgentName"] != "claude-code" {
		t.Errorf("child SessionTags[AgentName] = %q, want \"claude-code\"", childSess.SessionTags["AgentName"])
	}
	if childSess.SessionTags["Task"] != "deploy-lambda" {
		t.Errorf("child SessionTags[Task] = %q, want \"deploy-lambda\"", childSess.SessionTags["Task"])
	}
	if childSess.SessionTags["HumanSession"] != humanEmail {
		t.Errorf("child SessionTags[HumanSession] = %q, want %q", childSess.SessionTags["HumanSession"], humanEmail)
	}
	if childSess.EventsCount != 1 {
		t.Errorf("child EventsCount = %d, want 1", childSess.EventsCount)
	}

	parentRef := ref(personKey, "web#"+parentRoleID+"#"+creationDate, parentRoleID)
	parentSess, ok := sessions[parentRef]
	if !ok {
		t.Fatalf("parent session %q not found; keys: %v", parentRef, sessionKeys(sessions))
	}
	if parentSess.ChainedEventCount != 1 {
		t.Errorf("parent ChainedEventCount = %d, want 1", parentSess.ChainedEventCount)
	}
}
