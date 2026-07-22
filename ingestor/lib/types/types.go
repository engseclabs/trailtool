// Package types contains all struct definitions for CloudTrail events and DynamoDB records
// used by the ingestor.
package types

// CloudTrailLog represents the structure of a CloudTrail log file
type CloudTrailLog struct {
	Records []CloudTrailRecord `json:"Records"`
}

// SessionContext contains session information
type SessionContext struct {
	Attributes struct {
		CreationDate                 string `json:"creationDate,omitempty"`
		MfaAuthenticated             string `json:"mfaAuthenticated,omitempty"`
		SessionCredentialFromConsole string `json:"sessionCredentialFromConsole,omitempty"`
	} `json:"attributes,omitempty"`
	// SignInSessionArn ties an event back to an AWS Sign-In OAuth session. It is present on
	// CreateOAuth2Token (the MCP OAuth grant) and, per the AWS MCP Server release, on every
	// subsequent AWS API call made with the resulting OAuth access token (aws:SignInSessionArn
	// context). This is the correlation key for attributing agent traffic to its OAuth grant.
	SignInSessionArn string `json:"signInSessionArn,omitempty"`
	// SourceIdentity is the identity string set at assume-role time, immutable through the
	// role-assumption chain. Usually absent unless STS/trust policies propagate it — parsed
	// for observability, never used as an identity key.
	SourceIdentity string `json:"sourceIdentity,omitempty"`
	SessionIssuer  struct {
		Type        string `json:"type,omitempty"`
		PrincipalID string `json:"principalId,omitempty"`
		ARN         string `json:"arn,omitempty"`
		AccountID   string `json:"accountId,omitempty"`
		UserName    string `json:"userName,omitempty"`
	} `json:"sessionIssuer,omitempty"`
}

// CloudTrailRecord represents a single CloudTrail event
type CloudTrailRecord struct {
	EventVersion string `json:"eventVersion"`
	// EventID is CloudTrail's GUID for the event — the in-batch dedupe key (org trails
	// duplicate global-service events across region files) and the last-resort
	// credential-group key for events with no credential at all.
	EventID                      string               `json:"eventID,omitempty"`
	EventTime                    string               `json:"eventTime"`
	EventName                    string               `json:"eventName"`
	EventSource                  string               `json:"eventSource"`
	EventType                    string               `json:"eventType,omitempty"`
	AwsRegion                    string               `json:"awsRegion,omitempty"`
	RecipientAccountID           string               `json:"recipientAccountId,omitempty"`
	UserIdentity                 UserIdentity         `json:"userIdentity"`
	SourceIPAddress              string               `json:"sourceIPAddress,omitempty"`
	UserAgent                    string               `json:"userAgent,omitempty"`
	SessionCredentialFromConsole string               `json:"sessionCredentialFromConsole,omitempty"`
	SessionContext               *SessionContext      `json:"sessionContext,omitempty"`
	RequestParameters            interface{}          `json:"requestParameters,omitempty"`
	ResponseElements             interface{}          `json:"responseElements,omitempty"`
	AdditionalEventData          interface{}          `json:"additionalEventData,omitempty"`
	ReadOnly                     *bool                `json:"readOnly,omitempty"`
	Resources                    []CloudTrailResource `json:"resources,omitempty"`
	ErrorCode                    string               `json:"errorCode,omitempty"`
	ErrorMessage                 string               `json:"errorMessage,omitempty"`
}

// CloudTrailResource represents the optional resources array in CloudTrail events
type CloudTrailResource struct {
	ARN       string `json:"ARN"`
	AccountID string `json:"accountId"`
	Type      string `json:"type"`
}

// OnBehalfOf identifies the IAM Identity Center user a request was made on behalf of.
// It names the stable human principal in the identity store independent of
// role-assumption and credential-refresh churn — the tier-1 identity key.
type OnBehalfOf struct {
	UserID           string `json:"userId,omitempty"`
	IdentityStoreARN string `json:"identityStoreArn,omitempty"`
}

// UserIdentity represents the user that made the request
type UserIdentity struct {
	Type           string          `json:"type"`
	PrincipalID    string          `json:"principalId"`
	ARN            string          `json:"arn"`
	AccountID      string          `json:"accountId,omitempty"`
	AccessKeyID    string          `json:"accessKeyId,omitempty"`
	UserName       string          `json:"userName,omitempty"`
	SessionContext *SessionContext `json:"sessionContext,omitempty"`
	// OnBehalfOf is a pointer so an absent element is distinguishable from an empty one.
	// Not all AWS services log it, so one session can mix events with and without it —
	// identity is resolved per credential group, never per event.
	OnBehalfOf *OnBehalfOf `json:"onBehalfOf,omitempty"`
	// InvokedBy names the AWS service calling on the human's behalf (forward-access
	// sessions, e.g. CloudFormation fan-out). Such events join the person's session but
	// are counted as service-driven and excluded from ClickOps flagging.
	InvokedBy string `json:"invokedBy,omitempty"`
	// CredentialID is the bearer-token credential handle on IdentityCenterUser events
	// (the access-portal session ID). Absent on role-session events — parsed for
	// observability, never used as an identity key.
	CredentialID string `json:"credentialId,omitempty"`
}

// DynamoDBRole represents an aggregated role record
type DynamoDBRole struct {
	CustomerID     string         `dynamodbav:"customerId"`
	ARN            string         `dynamodbav:"arn"`
	Name           string         `dynamodbav:"name"`
	AccountID      string         `dynamodbav:"account_id"`
	LastSeen       string         `dynamodbav:"last_seen"`
	FirstSeen      string         `dynamodbav:"first_seen"`
	TotalEvents    int            `dynamodbav:"total_events"`
	ServicesUsed   []string       `dynamodbav:"services_used"`
	ServicesCount  map[string]int `dynamodbav:"services_count"`
	ResourcesUsed  []string       `dynamodbav:"resources_used"`
	ResourcesCount map[string]int `dynamodbav:"resources_count"`
	TopEventNames  map[string]int `dynamodbav:"top_event_names"`
	// Resource access tracking (similar to sessions)
	ResourceAccesses []ResourceAccessItem `dynamodbav:"resource_accesses,omitempty"`
	// Access Denied tracking
	TotalDeniedEvents      int                  `dynamodbav:"total_denied_events,omitempty"`
	TopDeniedEventNames    map[string]int       `dynamodbav:"top_denied_event_names,omitempty"`
	DeniedResourceAccesses []ResourceAccessItem `dynamodbav:"denied_resource_accesses,omitempty"`
	DeniedEventAccesses    []EventAccessItem    `dynamodbav:"denied_event_accesses,omitempty"` // detailed denied event access tracking (for events without specific resources)
	// New aggregated counts for noun-based architecture
	PeopleCount   int `dynamodbav:"people_count"`
	SessionsCount int `dynamodbav:"sessions_count"`
	AccountsCount int `dynamodbav:"accounts_count"`
}

// ResourceAccessItem tracks resource access details for aggregation
type ResourceAccessItem struct {
	Resource     string `dynamodbav:"resource"`
	Service      string `dynamodbav:"service"`
	EventName    string `dynamodbav:"event_name"`
	Count        int    `dynamodbav:"count"`
	PolicyARN    string `dynamodbav:"policy_arn,omitempty"`    // ARN of denying policy (AWS Jan 2026)
	PolicyType   string `dynamodbav:"policy_type,omitempty"`   // Type: SCP, RCP, identity-based, session, permission-boundary
	ErrorMessage string `dynamodbav:"error_message,omitempty"` // Full CloudTrail error message for context
}

// EventAccessItem tracks event access details for aggregation (for events without specific resources)
type EventAccessItem struct {
	Service      string `dynamodbav:"service"`
	EventName    string `dynamodbav:"event_name"`
	Count        int    `dynamodbav:"count"`
	PolicyARN    string `dynamodbav:"policy_arn,omitempty"`    // ARN of denying policy (AWS Jan 2026)
	PolicyType   string `dynamodbav:"policy_type,omitempty"`   // Type: SCP, RCP, identity-based, session, permission-boundary
	ErrorMessage string `dynamodbav:"error_message,omitempty"` // Full CloudTrail error message for context
}

// DynamoDBService represents an aggregated service record
type DynamoDBService struct {
	CustomerID     string         `dynamodbav:"customerId"`
	EventSource    string         `dynamodbav:"event_source"`
	DisplayName    string         `dynamodbav:"display_name"`
	Category       string         `dynamodbav:"category"`
	TotalEvents    int            `dynamodbav:"total_events"`
	RolesUsing     []string       `dynamodbav:"roles_using"`
	RolesCount     int            `dynamodbav:"roles_count"`
	ResourcesUsed  []string       `dynamodbav:"resources_used"`
	ResourcesCount int            `dynamodbav:"resources_count"`
	TopEventNames  map[string]int `dynamodbav:"top_event_names"`
	FirstSeen      string         `dynamodbav:"first_seen"`
	LastSeen       string         `dynamodbav:"last_seen"`
	// Access Denied tracking
	TotalDeniedEvents   int            `dynamodbav:"total_denied_events,omitempty"`
	TopDeniedEventNames map[string]int `dynamodbav:"top_denied_event_names,omitempty"`
	// New aggregated counts for noun-based architecture
	PeopleCount   int `dynamodbav:"people_count"`
	SessionsCount int `dynamodbav:"sessions_count"`
	AccountsCount int `dynamodbav:"accounts_count"`
}

// ClickOpsAccess represents a ClickOps (web console) modification to a resource
type ClickOpsAccess struct {
	SessionRef string `dynamodbav:"session_ref"` // person_key|sk of the session that performed it
	PersonKey  string `dynamodbav:"person_key"`  // Who performed the operation
	EventName  string `dynamodbav:"event_name"`  // What operation (CreateBucket, PutObject, UpdateFunction, etc.)
	AccessTime string `dynamodbav:"access_time"` // ISO8601 timestamp of session start time
	EventCount int    `dynamodbav:"event_count"` // Number of times this operation performed in this session
	AccountID  string `dynamodbav:"account_id"`  // AWS account ID
}

// DynamoDBResource represents an aggregated resource record
type DynamoDBResource struct {
	CustomerID    string         `dynamodbav:"customerId"`
	Identifier    string         `dynamodbav:"identifier"`
	Type          string         `dynamodbav:"type"`
	ARN           string         `dynamodbav:"arn"`
	Name          string         `dynamodbav:"name"`
	AccountID     string         `dynamodbav:"account_id"`
	TotalEvents   int            `dynamodbav:"total_events"`
	RolesUsing    []string       `dynamodbav:"roles_using"`
	RolesCount    int            `dynamodbav:"roles_count"`
	ServicesUsed  []string       `dynamodbav:"services_used"`
	TopEventNames map[string]int `dynamodbav:"top_event_names"`
	FirstSeen     string         `dynamodbav:"first_seen"`
	LastSeen      string         `dynamodbav:"last_seen"`
	// Access Denied tracking
	TotalDeniedEvents   int            `dynamodbav:"total_denied_events,omitempty"`
	TopDeniedEventNames map[string]int `dynamodbav:"top_denied_event_names,omitempty"`
	// New aggregated counts for noun-based architecture
	PeopleCount   int `dynamodbav:"people_count"`
	SessionsCount int `dynamodbav:"sessions_count"`
	// ClickOps tracking - tracks all web console create/modify operations on this resource
	ClickOpsAccesses []ClickOpsAccess `dynamodbav:"clickops_accesses,omitempty"`
	ClickOpsCount    int              `dynamodbav:"clickops_count"` // Total ClickOps events across all sessions
}

// DynamoDBPerson represents a person record in trailtool-people, keyed by the
// tier-prefixed person key (idc#…, email#…, iamuser#…, root#…) resolved per
// credential group. Email→person is one-to-many: offboard/rehire mints a new
// Identity Center userId for the same email, and the same human may exist under
// idc# and email# keys across an Identity Center adoption.
type DynamoDBPerson struct {
	CustomerID string `dynamodbav:"customerId"` // HASH
	PersonKey  string `dynamodbav:"person_key"` // RANGE
	Tier       int    `dynamodbav:"tier"`       // resolution tier the key came from (1–5)
	// Email is the primary observed email (email_index GSI range key). Identity
	// Center usernames are not required to be emails: non-email session names land
	// in EmailsSeen (they're the username) but never become an Email.
	Email          string   `dynamodbav:"email,omitempty"`
	EmailsSeen     []string `dynamodbav:"emails_seen,omitempty"`
	DisplayName    string   `dynamodbav:"display_name,omitempty"`
	FirstSeen      string   `dynamodbav:"first_seen"`
	LastSeen       string   `dynamodbav:"last_seen"`
	SessionsCount  int      `dynamodbav:"sessions_count"`
	AccountsCount  int      `dynamodbav:"accounts_count"`
	RolesCount     int      `dynamodbav:"roles_count"`
	ServicesCount  int      `dynamodbav:"services_count"`
	ResourcesCount int      `dynamodbav:"resources_count"`
	EventsCount    int      `dynamodbav:"events_count"`
}

// ResourceAccess represents a detailed resource access record
type ResourceAccess struct {
	Resource     string `dynamodbav:"resource"`   // e.g., "s3:bucket:my-bucket"
	Service      string `dynamodbav:"service"`    // e.g., "s3.amazonaws.com"
	EventName    string `dynamodbav:"event_name"` // e.g., "PutObject"
	Count        int    `dynamodbav:"count"`
	PolicyARN    string `dynamodbav:"policy_arn,omitempty"`    // ARN of denying policy (from Jan 2026 AWS update)
	PolicyType   string `dynamodbav:"policy_type,omitempty"`   // Type: SCP, RCP, identity-based, session, permission-boundary
	ErrorMessage string `dynamodbav:"error_message,omitempty"` // Full CloudTrail error message for context
}

// EventAccess represents a detailed event access record (for events without specific resources)
type EventAccess struct {
	Service      string `dynamodbav:"service"`    // e.g., "ce.amazonaws.com"
	EventName    string `dynamodbav:"event_name"` // e.g., "GetAnomalySubscriptions"
	Count        int    `dynamodbav:"count"`
	PolicyARN    string `dynamodbav:"policy_arn,omitempty"`    // ARN of denying policy (from Jan 2026 AWS update)
	PolicyType   string `dynamodbav:"policy_type,omitempty"`   // Type: SCP, RCP, identity-based, session, permission-boundary
	ErrorMessage string `dynamodbav:"error_message,omitempty"` // Full CloudTrail error message for context
}

// DynamoDBSession is a session record in trailtool-sessions: all events sharing
// one (person_key, roleID, anchor). The keys are deterministic, so cross-batch
// writes for the same credential hit the same item and merge additively — except
// windowed-fallback sessions (SK "win#…"), whose sort key is sticky
// (first-written start) and whose writes are guarded by Version.
type DynamoDBSession struct {
	PK string `dynamodbav:"pk"` // customerId#person_key — one Query lists a person's sessions
	SK string `dynamodbav:"sk"` // anchor#roleID, or win#roleID#firstWrittenStart for the fallback

	CustomerID  string `dynamodbav:"customerId"`
	PersonKey   string `dynamodbav:"person_key"`
	Anchor      string `dynamodbav:"anchor"`       // sis#… | web#… | key#… | win#… (fallback)
	SessionType string `dynamodbav:"session_type"` // cli | web | agent | login

	RoleARN    string `dynamodbav:"role_arn"`
	RoleID     string `dynamodbav:"role_id"`
	RoleName   string `dynamodbav:"role_name"`
	AccountID  string `dynamodbav:"account_id"`
	RoleKey    string `dynamodbav:"role_key"`    // customerId#role_id — role_index GSI hash
	AccountKey string `dynamodbav:"account_key"` // customerId#account_id — account_index GSI hash

	// True session bounds. For win# sessions the SK keeps the first-written start
	// even when a later batch extends the window earlier; StartTime moves instead.
	StartTime       string `dynamodbav:"start_time"`
	EndTime         string `dynamodbav:"end_time"`
	DurationMinutes int    `dynamodbav:"duration_minutes"`
	// Version is an optimistic-lock counter. Load-bearing only for win# sessions,
	// whose cross-batch extend/fold writes are conditional on it.
	Version int64 `dynamodbav:"version"`

	EventsCount int `dynamodbav:"events_count"`
	// ServiceDrivenEventCount counts events with userIdentity.invokedBy set: AWS
	// services calling with the human's credentials (forward-access sessions).
	// Included in EventsCount but excluded from ClickOps flagging.
	ServiceDrivenEventCount int              `dynamodbav:"service_driven_event_count,omitempty"`
	ServicesCount           int              `dynamodbav:"services_count"`
	ResourcesCount          int              `dynamodbav:"resources_count"`
	SourceIPs               []string         `dynamodbav:"source_ips"`
	UserAgents              []string         `dynamodbav:"user_agents"`
	EventCounts             map[string]int   `dynamodbav:"event_counts"`       // "eventSource:eventName" -> count
	ResourcesAccessed       map[string]int   `dynamodbav:"resources_accessed"` // resource identifier -> count
	ResourceAccesses        []ResourceAccess `dynamodbav:"resource_accesses"`

	// Access Denied tracking
	DeniedEventCount        int              `dynamodbav:"denied_event_count,omitempty"`
	DeniedEventCounts       map[string]int   `dynamodbav:"denied_event_counts,omitempty"`
	DeniedResourcesAccessed map[string]int   `dynamodbav:"denied_resources_accessed,omitempty"`
	DeniedResourceAccesses  []ResourceAccess `dynamodbav:"denied_resource_accesses,omitempty"`
	DeniedEventAccesses     []EventAccess    `dynamodbav:"denied_event_accesses,omitempty"`

	// ClickOps tracking — console create/modify operations in this session
	ClickOpsEventCount  int            `dynamodbav:"clickops_event_count,omitempty"`
	ClickOpsEventCounts map[string]int `dynamodbav:"clickops_event_counts,omitempty"`

	// SignInSessionArn is recorded whenever the session's events carried one
	// (whether or not the session anchored on it).
	SignInSessionArn string `dynamodbav:"sign_in_session_arn,omitempty"`

	// Role chaining — child fields. AssumedFromSession is a session ref
	// ("person_key|sk") pointing at the parent session that called AssumeRole.
	AssumedFromSession string `dynamodbav:"assumed_from_session,omitempty"`
	AssumedFromRoleARN string `dynamodbav:"assumed_from_role_arn,omitempty"`

	// Role chaining — parent fields.
	ChainedSessionRefs []string `dynamodbav:"chained_session_refs,omitempty"` // child session refs
	ChainedRoles       []string `dynamodbav:"chained_roles,omitempty"`        // role ARNs assumed during this session
	ChainedEventCount  int      `dynamodbav:"chained_event_count,omitempty"`  // events attributed to children (summary)

	// SessionTags/SessionPolicy come from the AssumeRole requestParameters that
	// created this child session.
	SessionTags   map[string]string `dynamodbav:"session_tags,omitempty"`
	SessionPolicy string            `dynamodbav:"session_policy,omitempty"`

	// aws login attribution: ref of the human session that authorized the
	// CreateOAuth2Token grant that vended this session's credentials.
	LoginGrantedBySession string `dynamodbav:"login_granted_by_session,omitempty"`

	// AWS MCP Server OAuth attribution (session_type "agent").
	MCPResource              string `dynamodbav:"mcp_resource,omitempty"`
	AgentAuthorizedBySession string `dynamodbav:"agent_authorized_by_session,omitempty"`
}

// DynamoDBIdentityLink is a record in trailtool-identity-links: the cross-batch
// correlation layer. One single-string PK with disjoint prefixes (§4.3), TTL 12h
// (STS max credential lifetime):
//
//	cred#<accessKeyId>                 credential → person + anchor (C1 continuity)
//	cred#<principalId>#<creationDate>  same, for console credential groups
//	chain#<issuedAccessKeyId>          AssumeRole child → person + parent session
//	chain#<assumedRoleID>#<eventTime>  same, console switch-role variant
//	login#<roleID>#<creationDate>      aws login (PKCE) grant → authorizing person
//	mcp#<signInSessionArn>             AWS MCP Server OAuth grant → authorizing person
type DynamoDBIdentityLink struct {
	PK        string `dynamodbav:"pk"`
	PersonKey string `dynamodbav:"person_key"`
	TTL       int64  `dynamodbav:"ttl"` // Unix timestamp — DynamoDB TTL

	// RoleARN and Anchor are set on cred# links: the resolved role and session
	// anchor of the credential group, so a later batch of the same credential
	// lands in the same session even when the anchor-deciding fields are absent.
	RoleARN string `dynamodbav:"role_arn,omitempty"`
	Anchor  string `dynamodbav:"anchor,omitempty"`

	// ParentSessionRef ("person_key|sk") points at the session that issued the
	// credential (chain#) or authorized the grant (login#, mcp#).
	// ParentRoleARN is that session's role.
	ParentSessionRef string `dynamodbav:"parent_session_ref,omitempty"`
	ParentRoleARN    string `dynamodbav:"parent_role_arn,omitempty"`

	// AssumedRoleARN, SessionTags, SessionPolicy are set on chain# links from the
	// AssumeRole request, and propagate to the child session record.
	AssumedRoleARN string            `dynamodbav:"assumed_role_arn,omitempty"`
	SessionTags    map[string]string `dynamodbav:"session_tags,omitempty"`
	SessionPolicy  string            `dynamodbav:"session_policy,omitempty"`

	// MCPResource is the AWS MCP Server resource from the grant's
	// requestParameters.resource. Set only on mcp# links.
	MCPResource string `dynamodbav:"mcp_resource,omitempty"`
}

// DynamoDBIngestedFile marks an S3 object as processed (trailtool-ingested-files):
// the file-level idempotency guard against S3/EventBridge redelivery.
type DynamoDBIngestedFile struct {
	ObjectKey  string `dynamodbav:"object_key"` // HASH — the S3 object key
	IngestedAt string `dynamodbav:"ingested_at"`
	TTL        int64  `dynamodbav:"ttl"` // Unix timestamp — DynamoDB TTL (30 days)
}

// DynamoDBAccount represents an aggregated account record
type DynamoDBAccount struct {
	CustomerID     string `dynamodbav:"customerId"`
	AccountID      string `dynamodbav:"account_id"`
	AccountName    string `dynamodbav:"account_name,omitempty"`
	FirstSeen      string `dynamodbav:"first_seen"`
	LastSeen       string `dynamodbav:"last_seen"`
	PeopleCount    int    `dynamodbav:"people_count"`
	SessionsCount  int    `dynamodbav:"sessions_count"`
	RolesCount     int    `dynamodbav:"roles_count"`
	ServicesCount  int    `dynamodbav:"services_count"`
	ResourcesCount int    `dynamodbav:"resources_count"`
	EventsCount    int    `dynamodbav:"events_count"`
}

// EventBridgeS3Event represents the S3 event wrapped by EventBridge
type EventBridgeS3Event struct {
	Version    string                 `json:"version"`
	ID         string                 `json:"id"`
	DetailType string                 `json:"detail-type"`
	Source     string                 `json:"source"`
	Account    string                 `json:"account"`
	Time       string                 `json:"time"`
	Region     string                 `json:"region"`
	Resources  []string               `json:"resources"`
	Detail     map[string]interface{} `json:"detail"`
}
