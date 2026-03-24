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
	SessionIssuer struct {
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

// UserIdentity represents the user that made the request
type UserIdentity struct {
	Type           string          `json:"type"`
	PrincipalID    string          `json:"principalId"`
	ARN            string          `json:"arn"`
	AccountID      string          `json:"accountId,omitempty"`
	AccessKeyID    string          `json:"accessKeyId,omitempty"`
	SessionContext *SessionContext `json:"sessionContext,omitempty"`
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
	Resource     string `dynamodbav:"resource"`                // e.g., "s3:bucket:my-bucket"
	Service      string `dynamodbav:"service"`                 // e.g., "s3.amazonaws.com"
	EventName    string `dynamodbav:"event_name"`              // e.g., "PutObject"
	Count        int    `dynamodbav:"count"`
	PolicyARN    string `dynamodbav:"policy_arn,omitempty"`    // ARN of denying policy (from Jan 2026 AWS update)
	PolicyType   string `dynamodbav:"policy_type,omitempty"`   // Type: SCP, RCP, identity-based, session, permission-boundary
	ErrorMessage string `dynamodbav:"error_message,omitempty"` // Full CloudTrail error message for context
}

// EventAccess represents a detailed event access record (for events without specific resources)
type EventAccess struct {
	Service      string `dynamodbav:"service"`                 // e.g., "ce.amazonaws.com"
	EventName    string `dynamodbav:"event_name"`              // e.g., "GetAnomalySubscriptions"
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
