// Package events builds and publishes TrailTool change events to EventBridge.
// Events report facts the ingestor just wrote (a new noun, a new edge, one
// session's slice of a CloudTrail file); they never score or judge them.
// Schemas and semantics: docs/design/events.md.
package events

import (
	"context"
	"encoding/json"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/service/eventbridge"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

const (
	// Source is the EventBridge source of every TrailTool event.
	Source = "trailtool"
	// SchemaVersion is bumped on any breaking change to a detail shape.
	SchemaVersion = 1

	DetailTypeNounCreated     = "TrailTool Noun Created"
	DetailTypeRelationCreated = "TrailTool Relation Created"
	DetailTypeSessionActivity = "TrailTool Session Activity"

	// MaxWrites caps Session Activity writes before the size guard trims more.
	MaxWrites = 50

	maxErrorMessageChars = 500
	maxRequestParamBytes = 2 * 1024
)

// Publisher is the subset of the EventBridge client Emit uses.
// *eventbridge.Client satisfies it.
type Publisher interface {
	PutEvents(ctx context.Context, params *eventbridge.PutEventsInput, optFns ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error)
}

// Event is one change event before serialization.
type Event struct {
	DetailType string
	Detail     any
}

// File names the CloudTrail object a batch came from.
type File struct {
	Key       string `json:"key"`
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
}

// Envelope is shared by every detail.
type Envelope struct {
	SchemaVersion int    `json:"schema_version"`
	CustomerID    string `json:"customer_id"`
	File          File   `json:"file"`
}

// NewEnvelope stamps the current schema version.
func NewEnvelope(customerID string, file File) Envelope {
	return Envelope{SchemaVersion: SchemaVersion, CustomerID: customerID, File: file}
}

// Record is a trimmed CloudTrail record. responseElements is never included.
type Record struct {
	EventID           string          `json:"event_id"`
	Time              string          `json:"time"`
	Event             string          `json:"event"`
	ErrorCode         string          `json:"error_code,omitempty"`
	ErrorMessage      string          `json:"error_message,omitempty"`
	RequestParameters json.RawMessage `json:"request_parameters,omitempty"`
	Resources         []Resource      `json:"resources,omitempty"`
	SourceIP          string          `json:"source_ip,omitempty"`
	UserAgent         string          `json:"user_agent,omitempty"`
	InvokedBy         string          `json:"invoked_by,omitempty"`
}

// Resource is one entry of a record's CloudTrail resources array.
type Resource struct {
	ARN       string `json:"arn,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Type      string `json:"type,omitempty"`
}

// Noun identifies one noun by kind and id.
type Noun struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// NounCreated is the detail of TrailTool Noun Created.
type NounCreated struct {
	Envelope
	Kind      string  `json:"kind"`
	ID        string  `json:"id"`
	FirstSeen string  `json:"first_seen"`
	Trigger   *Record `json:"trigger,omitempty"`
}

// RelationCreated is the detail of TrailTool Relation Created.
type RelationCreated struct {
	Envelope
	Subject   Noun   `json:"subject"`
	Related   Noun   `json:"related"`
	FirstSeen string `json:"first_seen"`
	// SubjectCounts are the subject's relation summary counts before this
	// batch's edges. Absent when the read failed.
	SubjectCounts map[string]int `json:"subject_counts,omitempty"`
	Trigger       *Record        `json:"trigger,omitempty"`
}

// Person identifies a session's person.
type Person struct {
	Key   string `json:"key"`
	Email string `json:"email,omitempty"`
	Label string `json:"label,omitempty"`
}

// Origin is how a session's credentials came to exist. Session references are
// sids.
type Origin struct {
	AssumedFromSession       string            `json:"assumed_from_session,omitempty"`
	AssumedFromRoleARN       string            `json:"assumed_from_role_arn,omitempty"`
	AgentAuthorizedBySession string            `json:"agent_authorized_by_session,omitempty"`
	MCPResource              string            `json:"mcp_resource,omitempty"`
	LoginGrantedBySession    string            `json:"login_granted_by_session,omitempty"`
	SessionTags              map[string]string `json:"session_tags,omitempty"`
	HasSessionPolicy         bool              `json:"has_session_policy"`
}

// SessionInfo identifies the session a Session Activity event describes.
type SessionInfo struct {
	Sid             string `json:"sid"`
	Person          Person `json:"person"`
	Type            string `json:"type"`
	AccountID       string `json:"account_id"`
	RoleARN         string `json:"role_arn"`
	RoleSessionName string `json:"role_session_name,omitempty"`
	NewSession      bool   `json:"new_session"`
	Origin          Origin `json:"origin"`
}

// Activity is what the session did in one file. Every field covers that file
// only, never the session's lifetime.
type Activity struct {
	Start              string                  `json:"start"`
	End                string                  `json:"end"`
	EventsCount        int                     `json:"events_count"`
	DeniedCount        int                     `json:"denied_count"`
	ServiceDrivenCount int                     `json:"service_driven_count"`
	ClickOpsCount      int                     `json:"clickops_count"`
	EventCounts        map[string]int          `json:"event_counts"`
	DeniedEventCounts  map[string]int          `json:"denied_event_counts,omitempty"`
	SourceIPs          []string                `json:"source_ips,omitempty"`
	Clients            []types.ClientAggregate `json:"clients,omitempty"`
	ChainedInto        []string                `json:"chained_into,omitempty"`
	// WriteCount is the number of mutating or denied calls before truncation;
	// Writes holds the earliest of them and WritesTruncated the rest.
	WriteCount      int      `json:"write_count"`
	Writes          []Record `json:"writes"`
	WritesTruncated int      `json:"writes_truncated"`
}

// SessionActivity is the detail of TrailTool Session Activity.
type SessionActivity struct {
	Envelope
	Session  SessionInfo `json:"session"`
	Activity Activity    `json:"activity"`
}

// Trim reduces a CloudTrail record to the fields events carry, bounding the
// two that can be large.
func Trim(r types.CloudTrailRecord) Record {
	out := Record{
		EventID:      r.EventID,
		Time:         r.EventTime,
		Event:        r.EventSource + ":" + r.EventName,
		ErrorCode:    r.ErrorCode,
		ErrorMessage: truncateChars(r.ErrorMessage, maxErrorMessageChars),
		SourceIP:     r.SourceIPAddress,
		UserAgent:    r.UserAgent,
		InvokedBy:    r.UserIdentity.InvokedBy,
	}
	for _, res := range r.Resources {
		out.Resources = append(out.Resources, Resource{ARN: res.ARN, AccountID: res.AccountID, Type: res.Type})
	}
	if r.RequestParameters != nil {
		if raw, err := json.Marshal(r.RequestParameters); err == nil {
			if len(raw) > maxRequestParamBytes {
				raw, _ = json.Marshal(map[string]any{"_truncated": true, "bytes": len(raw)})
			}
			out.RequestParameters = raw
		}
	}
	return out
}

func truncateChars(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
