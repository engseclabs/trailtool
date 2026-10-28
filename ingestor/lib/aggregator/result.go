package aggregator

import (
	"sort"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// Result describes what one ProcessWithResult call wrote, for change-event
// emission. It holds batch-local facts only and is never persisted.
type Result struct {
	// Namespace is the customer namespace the batch was written under.
	Namespace string

	// Sessions holds one entry per session written successfully, sorted by sid.
	Sessions []SessionResult

	// NewNouns are nouns this batch created anywhere for the first time, and
	// NewEdges the directed edges it created for the first time. Both come from
	// the relations table's create-if-absent puts, so a concurrent or replayed
	// batch never reports the same one twice. Sorted by key.
	NewNouns []NewNoun
	NewEdges []NewEdge

	// Records indexes the trigger events of NewNouns and NewEdges by eventID.
	Records map[string]types.CloudTrailRecord

	// byRef is the in-memory session map keyed by pre-write session ref.
	byRef map[string]*types.DynamoDBSession
}

// SessionResult is one session's slice of the batch.
type SessionResult struct {
	// Session carries only this batch's activity. Its SK and Sid are the
	// pre-write keys; use SK and Sid below.
	Session *types.DynamoDBSession

	// SK and Sid name the persisted survivor. A win# session can fold into an
	// earlier window, whose keys then win.
	SK  string
	Sid string

	// New is true when the write created the session rather than merging into
	// an existing one.
	New bool

	// Person is the batch's view of the session's person (nil when the batch
	// has none).
	Person *types.DynamoDBPerson

	// Writes holds the batch's mutating or denied calls in this session, in
	// event-time order.
	Writes []types.CloudTrailRecord
}

// NewNoun is a noun whose relation _summary this batch created.
type NewNoun struct {
	Kind      string
	ID        string
	FirstSeen string
	// TriggerEventID names the batch's earliest event touching the noun.
	TriggerEventID string
}

// NewEdge is a directed edge this batch created.
type NewEdge struct {
	types.DynamoDBRelation
	// SubjectNew is true when the subject noun is itself new in this batch,
	// so its summary counts before the batch were all zero.
	SubjectNew bool
	// TriggerEventID names the batch's earliest observation of the edge.
	TriggerEventID string
}

// credentialCalls are STS calls CloudTrail marks read-only that still mint
// new credentials. An audit trail of a session needs them, so they count as
// writes.
var credentialCalls = map[string]bool{
	"AssumeRole":                true,
	"AssumeRoleWithSAML":        true,
	"AssumeRoleWithWebIdentity": true,
	"AssumeRoot":                true,
	"GetFederationToken":        true,
	"GetSessionToken":           true,
}

// isWriteOrDenied reports whether a record belongs in a session's writes: a
// mutating call (readOnly false or absent), a credential-minting STS call, or
// any access-denied call.
func isWriteOrDenied(event types.CloudTrailRecord) bool {
	if event.ReadOnly == nil || !*event.ReadOnly {
		return true
	}
	if event.EventSource == "sts.amazonaws.com" && credentialCalls[event.EventName] {
		return true
	}
	return session.IsAccessDeniedError(event.ErrorCode)
}

// collectCreated turns the relation writer's created sets into the result's
// NewNouns and NewEdges, attaching each one's earliest batch observation.
func collectCreated(res *Result, relations relationCollector, newSubjects map[string]bool, newEdges []types.DynamoDBRelation) {
	if len(newSubjects) > 0 {
		// The earliest edge wins; ties go to the lowest key so the trigger is
		// deterministic without sorting the whole collector.
		type candidate struct {
			key  string
			edge collectedRelation
		}
		earliest := make(map[string]candidate, len(newSubjects))
		for key, edge := range relations {
			if !newSubjects[edge.PK] {
				continue
			}
			prior, ok := earliest[edge.PK]
			if !ok || edge.FirstSeen < prior.edge.FirstSeen ||
				(edge.FirstSeen == prior.edge.FirstSeen && key < prior.key) {
				earliest[edge.PK] = candidate{key: key, edge: edge}
			}
		}
		pks := make([]string, 0, len(earliest))
		for pk := range earliest {
			pks = append(pks, pk)
		}
		sort.Strings(pks)
		for _, pk := range pks {
			edge := earliest[pk].edge
			res.NewNouns = append(res.NewNouns, NewNoun{
				Kind:           edge.SubjectKind,
				ID:             edge.SubjectID,
				FirstSeen:      edge.FirstSeen,
				TriggerEventID: edge.TriggerEventID,
			})
		}
	}
	for _, edge := range newEdges {
		res.NewEdges = append(res.NewEdges, NewEdge{
			DynamoDBRelation: edge,
			SubjectNew:       newSubjects[edge.PK],
			TriggerEventID:   relations[edge.PK+"\x00"+edge.SK].TriggerEventID,
		})
	}
}

// indexTriggers fills res.Records with the events NewNouns and NewEdges name.
func indexTriggers(res *Result, groups []identity.Group) {
	wanted := make(map[string]bool)
	for _, noun := range res.NewNouns {
		if noun.TriggerEventID != "" {
			wanted[noun.TriggerEventID] = true
		}
	}
	for _, edge := range res.NewEdges {
		if edge.TriggerEventID != "" {
			wanted[edge.TriggerEventID] = true
		}
	}
	if len(wanted) == 0 {
		return
	}
	res.Records = make(map[string]types.CloudTrailRecord, len(wanted))
	for _, group := range groups {
		for _, event := range group.Events {
			if wanted[event.EventID] {
				res.Records[event.EventID] = event
			}
		}
	}
}

func sortSessionResults(results []SessionResult) {
	sort.Slice(results, func(i, j int) bool { return results[i].Sid < results[j].Sid })
	for _, r := range results {
		sort.SliceStable(r.Writes, func(i, j int) bool {
			return r.Writes[i].EventTime < r.Writes[j].EventTime
		})
	}
}
