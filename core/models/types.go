package models

import "strings"

// Person represents an aggregated person record from the people-aggregated table
type Person struct {
	Email          string `json:"email" dynamodbav:"email"`
	DisplayName    string `json:"display_name,omitempty" dynamodbav:"display_name"`
	FirstSeen      string `json:"first_seen" dynamodbav:"first_seen"`
	LastSeen       string `json:"last_seen" dynamodbav:"last_seen"`
	SessionsCount  int    `json:"sessions_count" dynamodbav:"sessions_count"`
	AccountsCount  int    `json:"accounts_count" dynamodbav:"accounts_count"`
	RolesCount     int    `json:"roles_count" dynamodbav:"roles_count"`
	ServicesCount  int    `json:"services_count" dynamodbav:"services_count"`
	ResourcesCount int    `json:"resources_count" dynamodbav:"resources_count"`
	EventsCount    int    `json:"events_count" dynamodbav:"events_count"`
}

// SessionAggregated represents an aggregated session record from the sessions-aggregated table
type SessionAggregated struct {
	SessionID         string           `json:"session_id" dynamodbav:"session_id"`
	SessionType       string           `json:"session_type,omitempty" dynamodbav:"session_type"`
	StartTime         string           `json:"start_time" dynamodbav:"start_time"`
	EndTime           string           `json:"end_time" dynamodbav:"end_time"`
	DurationMinutes   int              `json:"duration_minutes" dynamodbav:"duration_minutes"`
	PersonEmail       string           `json:"person_email" dynamodbav:"person_email"`
	AccountID         string           `json:"account_id" dynamodbav:"account_id"`
	RoleARN           string           `json:"role_arn" dynamodbav:"role_arn"`
	RoleName          string           `json:"role_name" dynamodbav:"role_name"`
	EventsCount       int              `json:"events_count" dynamodbav:"events_count"`
	ServicesCount     int              `json:"services_count" dynamodbav:"services_count"`
	ResourcesCount    int              `json:"resources_count" dynamodbav:"resources_count"`
	SourceIPs         []string         `json:"source_ips" dynamodbav:"source_ips"`
	UserAgents        []string         `json:"user_agents" dynamodbav:"user_agents"`
	EventCounts       map[string]int   `json:"event_counts" dynamodbav:"event_counts"`
	ResourcesAccessed map[string]int   `json:"resources_accessed" dynamodbav:"resources_accessed"`
	ResourceAccesses  []ResourceAccess `json:"resource_accesses,omitempty" dynamodbav:"resource_accesses"`

	// Access Denied tracking
	DeniedEventCount        int              `json:"denied_event_count,omitempty" dynamodbav:"denied_event_count"`
	DeniedEventCounts       map[string]int   `json:"denied_event_counts,omitempty" dynamodbav:"denied_event_counts"`
	DeniedResourcesAccessed map[string]int   `json:"denied_resources_accessed,omitempty" dynamodbav:"denied_resources_accessed"`
	DeniedResourceAccesses  []ResourceAccess `json:"denied_resource_accesses,omitempty" dynamodbav:"denied_resource_accesses"`
	DeniedEventAccesses     []EventAccess    `json:"denied_event_accesses,omitempty" dynamodbav:"denied_event_accesses"`

	// AI summary cache
	Summary            string `json:"summary,omitempty" dynamodbav:"summary,omitempty"`
	SummaryGeneratedAt string `json:"summary_generated_at,omitempty" dynamodbav:"summary_generated_at,omitempty"`
	SummaryModel       string `json:"summary_model,omitempty" dynamodbav:"summary_model,omitempty"`
	SummaryTokensUsed  int    `json:"summary_tokens_used,omitempty" dynamodbav:"summary_tokens_used,omitempty"`

	// Display enrichment
	PersonDisplayName string `json:"person_display_name,omitempty"`
	AccountName       string `json:"account_name,omitempty"`

	// ClickOps tracking
	ClickOpsEventCount  int            `json:"clickops_event_count,omitempty" dynamodbav:"clickops_event_count"`
	ClickOpsEventCounts map[string]int `json:"clickops_event_counts,omitempty" dynamodbav:"clickops_event_counts"`
}

// DetectSessionType determines the session type from user agents
func (s *SessionAggregated) DetectSessionType() string {
	if len(s.UserAgents) == 0 {
		return "API"
	}
	ua := strings.ToLower(s.UserAgents[0])
	if strings.Contains(ua, "console.aws.amazon.com") {
		return "Console"
	}
	if strings.Contains(ua, "aws-cli") || strings.Contains(ua, "boto3") || strings.Contains(ua, "terraform") {
		return "CLI/SDK"
	}
	return "API"
}

// Role represents an aggregated role record from the roles-aggregated table
type Role struct {
	ARN            string            `json:"arn" dynamodbav:"arn"`
	Name           string            `json:"name" dynamodbav:"name"`
	AccountID      string            `json:"account_id" dynamodbav:"account_id"`
	LastSeen       string            `json:"last_seen" dynamodbav:"last_seen"`
	FirstSeen      string            `json:"first_seen" dynamodbav:"first_seen"`
	TotalEvents    int               `json:"total_events" dynamodbav:"total_events"`
	ServicesUsed   []string          `json:"services_used" dynamodbav:"services_used"`
	ServicesCount  map[string]int    `json:"services_count" dynamodbav:"services_count"`
	ResourcesUsed  []string          `json:"resources_used" dynamodbav:"resources_used"`
	ResourcesCount map[string]int    `json:"resources_count" dynamodbav:"resources_count"`
	TopEventNames  map[string]int    `json:"top_event_names" dynamodbav:"top_event_names"`
	ResourceAccesses []ResourceAccessItem `json:"resource_accesses,omitempty" dynamodbav:"resource_accesses,omitempty"`

	// Access Denied tracking
	TotalDeniedEvents      int                  `json:"total_denied_events,omitempty" dynamodbav:"total_denied_events"`
	TopDeniedEventNames    map[string]int       `json:"top_denied_event_names,omitempty" dynamodbav:"top_denied_event_names"`
	DeniedResourceAccesses []ResourceAccessItem `json:"denied_resource_accesses,omitempty" dynamodbav:"denied_resource_accesses"`
	DeniedEventAccesses    []EventAccessItem    `json:"denied_event_accesses,omitempty" dynamodbav:"denied_event_accesses"`

	// Counts
	PeopleCount   int `json:"people_count" dynamodbav:"people_count"`
	SessionsCount int `json:"sessions_count" dynamodbav:"sessions_count"`
	AccountsCount int `json:"accounts_count" dynamodbav:"accounts_count"`
}

// ResourceAccess represents a detailed resource access record
type ResourceAccess struct {
	Resource     string `json:"resource" dynamodbav:"resource"`
	Service      string `json:"service" dynamodbav:"service"`
	EventName    string `json:"event_name" dynamodbav:"event_name"`
	Count        int    `json:"count" dynamodbav:"count"`
	PolicyARN    string `json:"policy_arn,omitempty" dynamodbav:"policy_arn"`
	PolicyType   string `json:"policy_type,omitempty" dynamodbav:"policy_type"`
	ErrorMessage string `json:"error_message,omitempty" dynamodbav:"error_message"`
}

// EventAccess represents a detailed event access record (for events without specific resources)
type EventAccess struct {
	Service      string `json:"service" dynamodbav:"service"`
	EventName    string `json:"event_name" dynamodbav:"event_name"`
	Count        int    `json:"count" dynamodbav:"count"`
	PolicyARN    string `json:"policy_arn,omitempty" dynamodbav:"policy_arn"`
	PolicyType   string `json:"policy_type,omitempty" dynamodbav:"policy_type"`
	ErrorMessage string `json:"error_message,omitempty" dynamodbav:"error_message"`
}

// ResourceAccessItem tracks resource access details for role aggregation
type ResourceAccessItem struct {
	Resource     string `json:"resource" dynamodbav:"resource"`
	Service      string `json:"service" dynamodbav:"service"`
	EventName    string `json:"event_name" dynamodbav:"event_name"`
	Count        int    `json:"count" dynamodbav:"count"`
	PolicyARN    string `json:"policy_arn,omitempty" dynamodbav:"policy_arn"`
	PolicyType   string `json:"policy_type,omitempty" dynamodbav:"policy_type"`
	ErrorMessage string `json:"error_message,omitempty" dynamodbav:"error_message"`
}

// EventAccessItem tracks event access details for role aggregation
type EventAccessItem struct {
	Service      string `json:"service" dynamodbav:"service"`
	EventName    string `json:"event_name" dynamodbav:"event_name"`
	Count        int    `json:"count" dynamodbav:"count"`
	PolicyARN    string `json:"policy_arn,omitempty" dynamodbav:"policy_arn"`
	PolicyType   string `json:"policy_type,omitempty" dynamodbav:"policy_type"`
	ErrorMessage string `json:"error_message,omitempty" dynamodbav:"error_message"`
}
