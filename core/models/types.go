package models

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Person represents a person record from the trailtool-people table, keyed by
// the tier-prefixed person key (idc#…, email#…, iamuser#…, root#…) resolved by
// the ingestor's identity tiers.
type Person struct {
	PersonKey      string   `json:"person_key" dynamodbav:"person_key"`
	Tier           int      `json:"tier,omitempty" dynamodbav:"tier"`
	Email          string   `json:"email,omitempty" dynamodbav:"email"`
	EmailsSeen     []string `json:"emails_seen,omitempty" dynamodbav:"emails_seen"`
	DisplayName    string   `json:"display_name,omitempty" dynamodbav:"display_name"`
	FirstSeen      string   `json:"first_seen" dynamodbav:"first_seen"`
	LastSeen       string   `json:"last_seen" dynamodbav:"last_seen"`
	SessionsCount  int      `json:"sessions_count" dynamodbav:"sessions_count"`
	AccountsCount  int      `json:"accounts_count" dynamodbav:"accounts_count"`
	RolesCount     int      `json:"roles_count" dynamodbav:"roles_count"`
	ServicesCount  int      `json:"services_count" dynamodbav:"services_count"`
	ResourcesCount int      `json:"resources_count" dynamodbav:"resources_count"`
	EventsCount    int      `json:"events_count" dynamodbav:"events_count"`
}

// DisplayLabel returns the friendliest identifier for the person: display
// name, then primary email, then the person key itself.
func (p *Person) DisplayLabel() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	if p.Email != "" {
		return p.Email
	}
	return p.PersonKey
}

// Session represents a session record from the trailtool-sessions table: all
// events sharing one (person_key, roleID, anchor). The sort key is the anchor
// (sis#/web#/key#, or win# for the windowed fallback), not a timestamp.
type Session struct {
	PK string `json:"-" dynamodbav:"pk"`  // customerId#person_key
	SK string `json:"sk" dynamodbav:"sk"` // anchor#roleID | win#roleID#start

	// Sid is the short deterministic session id (sort key of the sid_index GSI).
	// The CLI shows a prefix of it and resolves "--session <prefix>" against the
	// index. Written by the ingestor; empty on records ingested before sids.
	Sid string `json:"sid,omitempty" dynamodbav:"sid"`

	PersonKey   string `json:"person_key" dynamodbav:"person_key"`
	Anchor      string `json:"anchor,omitempty" dynamodbav:"anchor"`
	SessionType string `json:"session_type,omitempty" dynamodbav:"session_type"` // cli | web | agent | login

	StartTime       string `json:"start_time" dynamodbav:"start_time"`
	EndTime         string `json:"end_time" dynamodbav:"end_time"`
	DurationMinutes int    `json:"duration_minutes" dynamodbav:"duration_minutes"`

	AccountID string `json:"account_id" dynamodbav:"account_id"`
	RoleARN   string `json:"role_arn" dynamodbav:"role_arn"`
	RoleID    string `json:"role_id,omitempty" dynamodbav:"role_id"`
	RoleName  string `json:"role_name" dynamodbav:"role_name"`

	EventsCount int `json:"events_count" dynamodbav:"events_count"`
	// ServiceDrivenEventCount counts events an AWS service made with the
	// human's credentials (userIdentity.invokedBy set).
	ServiceDrivenEventCount int              `json:"service_driven_event_count,omitempty" dynamodbav:"service_driven_event_count"`
	ServicesCount           int              `json:"services_count" dynamodbav:"services_count"`
	ResourcesCount          int              `json:"resources_count" dynamodbav:"resources_count"`
	SourceIPs               []string         `json:"source_ips" dynamodbav:"source_ips"`
	UserAgents              []string         `json:"user_agents" dynamodbav:"user_agents"`
	EventCounts             map[string]int   `json:"event_counts" dynamodbav:"event_counts"`
	ResourcesAccessed       map[string]int   `json:"resources_accessed" dynamodbav:"resources_accessed"`
	ResourceAccesses        []ResourceAccess `json:"resource_accesses,omitempty" dynamodbav:"resource_accesses"`

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

	// Display enrichment (not stored)
	PersonLabel string `json:"person_label,omitempty" dynamodbav:"-"`
	AccountName string `json:"account_name,omitempty" dynamodbav:"-"`

	// ClickOps tracking
	ClickOpsEventCount  int            `json:"clickops_event_count,omitempty" dynamodbav:"clickops_event_count"`
	ClickOpsEventCounts map[string]int `json:"clickops_event_counts,omitempty" dynamodbav:"clickops_event_counts"`

	// SignInSessionArn is recorded whenever the session's events carried one.
	SignInSessionArn string `json:"sign_in_session_arn,omitempty" dynamodbav:"sign_in_session_arn"`

	// Role chaining — child fields. AssumedFromSession is a session ref
	// ("person_key|sk") pointing at the parent session that ran AssumeRole.
	AssumedFromSession string `json:"assumed_from_session,omitempty" dynamodbav:"assumed_from_session"`
	AssumedFromRoleARN string `json:"assumed_from_role_arn,omitempty" dynamodbav:"assumed_from_role_arn"`

	// Role chaining — parent fields.
	ChainedSessionRefs []string `json:"chained_session_refs,omitempty" dynamodbav:"chained_session_refs"`
	ChainedRoles       []string `json:"chained_roles,omitempty" dynamodbav:"chained_roles"`
	ChainedEventCount  int      `json:"chained_event_count,omitempty" dynamodbav:"chained_event_count"`

	// GrantedSessionRefs is the parent side of aws login / MCP attribution:
	// refs of sessions whose credentials this session authorized via an OAuth
	// grant.
	GrantedSessionRefs []string `json:"granted_session_refs,omitempty" dynamodbav:"granted_session_refs"`

	// aws login attribution — ref of the authorizing human session.
	LoginGrantedBySession string `json:"login_granted_by_session,omitempty" dynamodbav:"login_granted_by_session"`

	// AWS MCP Server OAuth attribution (session_type "agent").
	MCPResource              string `json:"mcp_resource,omitempty" dynamodbav:"mcp_resource"`
	AgentAuthorizedBySession string `json:"agent_authorized_by_session,omitempty" dynamodbav:"agent_authorized_by_session"`

	// SessionTags holds the session tags from the AssumeRole requestParameters.tags
	// that created this child session. Non-nil only on chained sessions.
	SessionTags map[string]string `json:"session_tags,omitempty" dynamodbav:"session_tags,omitempty"`

	// SessionPolicy is the raw inline IAM policy from requestParameters.policy in the
	// AssumeRole event that created this child session. Stored as a JSON string.
	SessionPolicy string `json:"session_policy,omitempty" dynamodbav:"session_policy,omitempty"`
}

// Ref returns the session's stable reference ("person_key|sk") — the format
// chained/login/MCP attribution fields use to point at other sessions.
func (s *Session) Ref() string {
	return s.PersonKey + "|" + s.SK
}

// sidLength mirrors identity.SidLength on the ingestor side. The two trees don't
// import each other (see core vs ingestor separation), so the algorithm is
// duplicated deliberately — like Ref() / SessionRef(). Keep them in sync.
const sidLength = 16

// SidForRef derives the deterministic session id from a ref ("person_key|sk").
// Used to print "--session <sid>" drilldown hints without re-fetching the target
// session, and it must produce the same value the ingestor stored.
func SidForRef(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return strings.ToLower(enc[:sidLength])
}

// SidForRef on the concrete session, from its own ref.
func (s *Session) SidForRef() string {
	return SidForRef(s.Ref())
}

// DetectSessionType returns a display label for the session type.
func (s *Session) DetectSessionType() string {
	switch s.SessionType {
	case "agent":
		return "AGENT"
	case "login":
		return "LOGIN"
	case "web":
		return "WEB"
	case "cli":
		return "CLI"
	default:
		return "API"
	}
}

// Role represents an aggregated role record from the roles-aggregated table
type Role struct {
	ARN              string               `json:"arn" dynamodbav:"arn"`
	Name             string               `json:"name" dynamodbav:"name"`
	AccountID        string               `json:"account_id" dynamodbav:"account_id"`
	LastSeen         string               `json:"last_seen" dynamodbav:"last_seen"`
	FirstSeen        string               `json:"first_seen" dynamodbav:"first_seen"`
	TotalEvents      int                  `json:"total_events" dynamodbav:"total_events"`
	ServicesUsed     []string             `json:"services_used" dynamodbav:"services_used"`
	ServicesCount    map[string]int       `json:"services_count" dynamodbav:"services_count"`
	ResourcesUsed    []string             `json:"resources_used" dynamodbav:"resources_used"`
	ResourcesCount   map[string]int       `json:"resources_count" dynamodbav:"resources_count"`
	TopEventNames    map[string]int       `json:"top_event_names" dynamodbav:"top_event_names"`
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

	// Enriched information
	AccountName string `json:"account_name,omitempty"`
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

// ClickOpsAccess represents a ClickOps (web console) modification to a resource
type ClickOpsAccess struct {
	SessionRef string `json:"session_ref" dynamodbav:"session_ref"` // person_key|sk of the session
	PersonKey  string `json:"person_key" dynamodbav:"person_key"`
	EventName  string `json:"event_name" dynamodbav:"event_name"`
	AccessTime string `json:"access_time" dynamodbav:"access_time"`
	EventCount int    `json:"event_count" dynamodbav:"event_count"`
	AccountID  string `json:"account_id" dynamodbav:"account_id"`
}

// Resource represents an aggregated resource record from the resources-aggregated table
type Resource struct {
	Identifier string `json:"identifier" dynamodbav:"identifier"`
	Type       string `json:"type" dynamodbav:"type"`
	ARN        string `json:"arn,omitempty" dynamodbav:"arn"`
	Name       string `json:"name" dynamodbav:"name"`
	AccountID  string `json:"account_id" dynamodbav:"account_id"`

	// Aggregated counts
	TotalEvents   int            `json:"total_events" dynamodbav:"total_events"`
	RolesUsing    []string       `json:"roles_using,omitempty" dynamodbav:"roles_using"`
	RolesCount    int            `json:"roles_count" dynamodbav:"roles_count"`
	ServicesUsed  []string       `json:"services_used,omitempty" dynamodbav:"services_used"`
	TopEventNames map[string]int `json:"top_event_names,omitempty" dynamodbav:"top_event_names"`

	// Access Denied tracking
	TotalDeniedEvents   int            `json:"total_denied_events,omitempty" dynamodbav:"total_denied_events"`
	TopDeniedEventNames map[string]int `json:"top_denied_event_names,omitempty" dynamodbav:"top_denied_event_names"`

	// Noun-based architecture counts
	PeopleCount   int `json:"people_count" dynamodbav:"people_count"`
	SessionsCount int `json:"sessions_count" dynamodbav:"sessions_count"`

	// ClickOps tracking
	ClickOpsAccesses []ClickOpsAccess `json:"clickops_accesses,omitempty" dynamodbav:"clickops_accesses"`
	ClickOpsCount    int              `json:"clickops_count" dynamodbav:"clickops_count"`

	// Activity tracking
	FirstSeen string `json:"first_seen" dynamodbav:"first_seen"`
	LastSeen  string `json:"last_seen" dynamodbav:"last_seen"`
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

// Account represents an aggregated account record from the accounts-aggregated table
type Account struct {
	AccountID   string `json:"account_id" dynamodbav:"account_id"`
	AccountName string `json:"account_name,omitempty" dynamodbav:"account_name"`
	FirstSeen   string `json:"first_seen" dynamodbav:"first_seen"`
	LastSeen    string `json:"last_seen" dynamodbav:"last_seen"`

	// Aggregated counts
	PeopleCount    int `json:"people_count" dynamodbav:"people_count"`
	SessionsCount  int `json:"sessions_count" dynamodbav:"sessions_count"`
	RolesCount     int `json:"roles_count" dynamodbav:"roles_count"`
	ServicesCount  int `json:"services_count" dynamodbav:"services_count"`
	ResourcesCount int `json:"resources_count" dynamodbav:"resources_count"`
	EventsCount    int `json:"events_count" dynamodbav:"events_count"`
}

// Service represents an aggregated AWS service record from the services-aggregated table
type Service struct {
	EventSource string `json:"event_source" dynamodbav:"event_source"`
	DisplayName string `json:"display_name" dynamodbav:"display_name"`
	Category    string `json:"category" dynamodbav:"category"`

	// Aggregated counts
	TotalEvents    int            `json:"total_events" dynamodbav:"total_events"`
	RolesUsing     []string       `json:"roles_using" dynamodbav:"roles_using"`
	RolesCount     int            `json:"roles_count" dynamodbav:"roles_count"`
	ResourcesUsed  []string       `json:"resources_used" dynamodbav:"resources_used"`
	ResourcesCount int            `json:"resources_count" dynamodbav:"resources_count"`
	TopEventNames  map[string]int `json:"top_event_names" dynamodbav:"top_event_names"`

	// Access Denied tracking
	TotalDeniedEvents   int            `json:"total_denied_events,omitempty" dynamodbav:"total_denied_events"`
	TopDeniedEventNames map[string]int `json:"top_denied_event_names,omitempty" dynamodbav:"top_denied_event_names"`

	// Noun-based architecture counts
	PeopleCount   int `json:"people_count" dynamodbav:"people_count"`
	SessionsCount int `json:"sessions_count" dynamodbav:"sessions_count"`
	AccountsCount int `json:"accounts_count" dynamodbav:"accounts_count"`

	// Activity tracking
	FirstSeen string `json:"first_seen" dynamodbav:"first_seen"`
	LastSeen  string `json:"last_seen" dynamodbav:"last_seen"`
}
