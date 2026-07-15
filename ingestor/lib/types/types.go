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
	SessionIssuer    struct {
		Type        string `json:"type,omitempty"`
		PrincipalID string `json:"principalId,omitempty"`
		ARN         string `json:"arn,omitempty"`
		AccountID   string `json:"accountId,omitempty"`
		UserName    string `json:"userName,omitempty"`
	} `json:"sessionIssuer,omitempty"`
}

// CloudTrailRecord represents a single CloudTrail event
type CloudTrailRecord struct {
	EventVersion                 string               `json:"eventVersion"`
	EventTime                    string               `json:"eventTime"`
	EventName                    string               `json:"eventName"`
	EventSource                  string               `json:"eventSource"`
	EventType                    string               `json:"eventType,omitempty"`
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

// OnBehalfOf identifies the AWS IAM Identity Center user a request was made on
// behalf of. Present on Identity Center (SSO) traffic, it names the stable human
// principal in the identity store independent of role-assumption churn, so it can
// outlive the ephemeral accessKeyId across credential refreshes.
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
	SessionContext *SessionContext `json:"sessionContext,omitempty"`
	// OnBehalfOf carries the Identity Center user id + identity-store ARN. It is a
	// pointer so an absent object is distinguishable from an empty one. Stable across
	// credential refreshes — a candidate cross-refresh session key (see probe).
	OnBehalfOf *OnBehalfOf `json:"onBehalfOf,omitempty"`
	// SourceIdentity is the string set at assume-role time; it is immutable through the
	// role-assumption chain. Often empty unless the permission set / trust policy
	// propagates it. Stable across credential refreshes.
	SourceIdentity string `json:"sourceIdentity,omitempty"`
	// CredentialID is a newer CloudTrail field: a stable credential handle that can
	// outlive a single ephemeral accessKeyId. Stable across credential refreshes.
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
	SessionID   string `dynamodbav:"session_id"`   // email:roleID (truncated session ID)
	PersonEmail string `dynamodbav:"person_email"` // Who performed the operation
	EventName   string `dynamodbav:"event_name"`   // What operation (CreateBucket, PutObject, UpdateFunction, etc.)
	AccessTime  string `dynamodbav:"access_time"`  // ISO8601 timestamp of session start time
	EventCount  int    `dynamodbav:"event_count"`  // Number of times this operation performed in this session
	AccountID   string `dynamodbav:"account_id"`   // AWS account ID
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

// DynamoDBPerson represents an aggregated person record
type DynamoDBPerson struct {
	CustomerID     string `dynamodbav:"customerId"`
	Email          string `dynamodbav:"email"`
	DisplayName    string `dynamodbav:"display_name,omitempty"`
	FirstSeen      string `dynamodbav:"first_seen"`
	LastSeen       string `dynamodbav:"last_seen"`
	SessionsCount  int    `dynamodbav:"sessions_count"`
	AccountsCount  int    `dynamodbav:"accounts_count"`
	RolesCount     int    `dynamodbav:"roles_count"`
	ServicesCount  int    `dynamodbav:"services_count"`
	ResourcesCount int    `dynamodbav:"resources_count"`
	EventsCount    int    `dynamodbav:"events_count"`
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

// DynamoDBSessionAggregated represents an aggregated session record
type DynamoDBSessionAggregated struct {
	CustomerID        string           `dynamodbav:"customerId"`
	SessionID         string           `dynamodbav:"session_id"`
	SessionType       string           `dynamodbav:"session_type"`  // "web-console" or "cli-sdk"
	SessionStart      string           `dynamodbav:"session_start"` // Range key - composite: "startTime#sessionID"
	StartTime         string           `dynamodbav:"start_time"`    // Pure timestamp for display/filtering
	EndTime           string           `dynamodbav:"end_time"`
	DurationMinutes   int              `dynamodbav:"duration_minutes"`
	PersonEmail       string           `dynamodbav:"person_email"`
	PersonDisplayName string           `dynamodbav:"person_display_name,omitempty"`
	AccountID         string           `dynamodbav:"account_id"`
	RoleARN           string           `dynamodbav:"role_arn"`
	RoleName          string           `dynamodbav:"role_name"`
	EventsCount       int              `dynamodbav:"events_count"`
	ServicesCount     int              `dynamodbav:"services_count"`
	ResourcesCount    int              `dynamodbav:"resources_count"`
	SourceIPs         []string         `dynamodbav:"source_ips"`
	UserAgents        []string         `dynamodbav:"user_agents"`
	EventCounts       map[string]int   `dynamodbav:"event_counts"`       // flattened "eventSource:eventName" -> count
	ResourcesAccessed map[string]int   `dynamodbav:"resources_accessed"` // resource identifier -> count
	ResourceAccesses  []ResourceAccess `dynamodbav:"resource_accesses"`  // detailed resource access tracking
	// Access Denied tracking
	DeniedEventCount        int              `dynamodbav:"denied_event_count,omitempty"`
	DeniedEventCounts       map[string]int   `dynamodbav:"denied_event_counts,omitempty"`       // flattened "eventSource:eventName" -> denied count
	DeniedResourcesAccessed map[string]int   `dynamodbav:"denied_resources_accessed,omitempty"` // resource identifier -> denied count
	DeniedResourceAccesses  []ResourceAccess `dynamodbav:"denied_resource_accesses,omitempty"`  // detailed denied resource access tracking
	DeniedEventAccesses     []EventAccess    `dynamodbav:"denied_event_accesses,omitempty"`     // detailed denied event access tracking (for events without specific resources)
	// ClickOps tracking - tracks console create/modify operations in this session
	ClickOpsEventCount  int            `dynamodbav:"clickops_event_count,omitempty"`  // Total ClickOps events in this session
	ClickOpsEventCounts map[string]int `dynamodbav:"clickops_event_counts,omitempty"` // Event name -> count for ClickOps operations
	// Role chaining — parent session fields (set on the originating human session)
	ChainedRoles       []string `dynamodbav:"chained_roles,omitempty"`        // Role ARNs assumed during this session
	ChainedEventCount  int      `dynamodbav:"chained_event_count,omitempty"`  // Events attributed via chaining (summary counter)
	ChainedSessionKeys []string `dynamodbav:"chained_session_keys,omitempty"` // session_start keys of child sessions (startTime#accessKeyID)

	// Role chaining — child session fields (set on sessions created for assumed roles)
	ParentSessionKey string `dynamodbav:"parent_session_key,omitempty"` // session_start key of the parent human session
	ParentEmail      string `dynamodbav:"parent_email,omitempty"`       // email of the human who initiated the chain

	// SessionTags holds the session tags from the AssumeRole requestParameters.tags that
	// created this child session. Only set on chained sessions whose parent AssumeRole
	// carried session tags (e.g. elhaz-vended agent credentials).
	SessionTags map[string]string `dynamodbav:"session_tags,omitempty"`

	// SessionPolicy is the raw inline IAM policy from requestParameters.policy in the
	// AssumeRole event. Stored as a JSON string exactly as captured by CloudTrail.
	SessionPolicy string `dynamodbav:"session_policy,omitempty"`

	// aws login attribution — set on the child session vended via CreateOAuth2Token.
	// The parent is the existing human session that authorized the aws login browser flow.
	// Correlation is by roleARN + sourceIP + creationDate within ±60s of CreateOAuth2Token.
	LoginGrantedBySessionKey string `dynamodbav:"login_granted_by_session_key,omitempty"` // session_start key of the authorizing session
	LoginGrantedByEmail      string `dynamodbav:"login_granted_by_email,omitempty"`       // email of the human who ran aws login

	// AWS MCP Server OAuth attribution — set on sessions whose events carry an
	// aws:SignInSessionArn matching a CreateOAuth2Token grant for the AWS MCP Server resource.
	// These represent agent traffic driven through the AWS MCP Server (SessionType "agent").
	SignInSessionArn         string `dynamodbav:"sign_in_session_arn,omitempty"`         // the OAuth sign-in session ARN correlating this session's events
	MCPResource              string `dynamodbav:"mcp_resource,omitempty"`                // the AWS MCP Server resource the OAuth grant targeted
	AgentAuthorizedBySession string `dynamodbav:"agent_authorized_by_session,omitempty"` // session_start key of the human session that authorized the MCP grant
	AgentAuthorizedByEmail   string `dynamodbav:"agent_authorized_by_email,omitempty"`   // email of the human who authorized the MCP grant
}

// DynamoDBChainLink records a temporary credential issued via AssumeRole,
// linking the issued access key back to the originating human session.
//
// The PK (access_key_id) is used in two ways:
//   - Programmatic sessions: the literal issued STS access key ID (ASIA...)
//   - Console switch-role sessions: "roleID:creationTime" composite key, since the
//     console issues a new short-lived credential per request rather than one
//     stable session credential.
type DynamoDBChainLink struct {
	AccessKeyID         string `dynamodbav:"access_key_id"`          // PK — issued key or "roleID:creationTime" for console
	ParentSessionMapKey string `dynamodbav:"parent_session_map_key"` // e.g. alice@example.com:AROAID...:2024-01-15T10:00:00Z
	ParentEmail         string `dynamodbav:"parent_email"`
	ParentRoleARN       string `dynamodbav:"parent_role_arn"`
	AssumedRoleARN      string `dynamodbav:"assumed_role_arn"` // role that was assumed
	TTL                 int64  `dynamodbav:"ttl"`              // Unix timestamp — DynamoDB TTL

	// SessionTags holds the session tags from the AssumeRole requestParameters.tags.
	// Propagated to the child session record so tag-based filtering works in later batches.
	SessionTags map[string]string `dynamodbav:"session_tags,omitempty"`

	// SessionPolicy is the raw inline IAM policy from requestParameters.policy.
	// Propagated to the child session record.
	SessionPolicy string `dynamodbav:"session_policy,omitempty"`

	// MCPResource is the AWS MCP Server resource from a CreateOAuth2Token grant's
	// requestParameters.resource. Non-empty only on MCP OAuth grant links, whose PK is
	// "mcp_grant:signInSessionArn". Used to tag correlated agent sessions.
	MCPResource string `dynamodbav:"mcp_resource,omitempty"`
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
