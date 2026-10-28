package events

import (
	"context"
	"log"

	"github.com/engseclabs/trailtool/ingestor/lib/aggregator"
	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/identity"
)

// CountsFunc reads a noun's current relation summary counts by relation PK.
type CountsFunc func(ctx context.Context, pk string) (map[string]int, error)

// emittedRelations lists the directions Relation Created reports. Both
// directions of every pair are written; consumers want each pair once, from
// the side that reads as "who reached what". Sessions are never reported:
// every session is new by definition.
var emittedRelations = map[string]map[string]bool{
	ddblib.RelationKindPerson: {
		ddblib.RelationKindAccount:  true,
		ddblib.RelationKindRole:     true,
		ddblib.RelationKindService:  true,
		ddblib.RelationKindResource: true,
	},
	ddblib.RelationKindRole: {
		ddblib.RelationKindAccount:  true,
		ddblib.RelationKindService:  true,
		ddblib.RelationKindResource: true,
	},
	ddblib.RelationKindAccount: {
		ddblib.RelationKindService:  true,
		ddblib.RelationKindResource: true,
	},
}

// EmitsRelation reports whether an edge direction gets a Relation Created event.
func EmitsRelation(subjectKind, relatedKind string) bool {
	return emittedRelations[subjectKind][relatedKind]
}

// BuildCreated builds Noun Created and Relation Created events for what the
// batch created. counts may be nil, which omits subject_counts for subjects
// that predate the batch.
func BuildCreated(ctx context.Context, env Envelope, res *aggregator.Result, counts CountsFunc) []Event {
	var out []Event
	for _, noun := range res.NewNouns {
		if noun.Kind == ddblib.RelationKindSession {
			continue
		}
		out = append(out, Event{DetailType: DetailTypeNounCreated, Detail: &NounCreated{
			Envelope:  env,
			Noun:      NewNoun(noun.Kind, noun.ID),
			FirstSeen: noun.FirstSeen,
			Trigger:   trigger(res, noun.TriggerEventID),
		}})
	}

	// Every created edge, emitted or not, bumped its subject's summary, so all
	// of them are subtracted from the post-write read.
	created := make(map[string]map[string]int)
	for _, edge := range res.NewEdges {
		if created[edge.PK] == nil {
			created[edge.PK] = make(map[string]int)
		}
		created[edge.PK][ddblib.RelationCountName(edge.RelatedKind)]++
	}
	before := make(map[string]map[string]int)
	for _, edge := range res.NewEdges {
		if !EmitsRelation(edge.SubjectKind, edge.RelatedKind) {
			continue
		}
		subjectCounts, read := before[edge.PK]
		if !read {
			subjectCounts = countsBefore(ctx, counts, edge, created[edge.PK])
			before[edge.PK] = subjectCounts
		}
		out = append(out, Event{DetailType: DetailTypeRelationCreated, Detail: &RelationCreated{
			Envelope:      env,
			Subject:       NewNoun(edge.SubjectKind, edge.SubjectID),
			Related:       NewNoun(edge.RelatedKind, edge.RelatedID),
			FirstSeen:     edge.FirstSeen,
			SubjectCounts: subjectCounts,
			Trigger:       trigger(res, edge.TriggerEventID),
		}})
	}
	return out
}

// countsBefore derives the subject's summary counts before this batch: zero
// for a subject the batch created, otherwise the post-write counts minus the
// batch's own new edges.
func countsBefore(ctx context.Context, counts CountsFunc, edge aggregator.NewEdge, created map[string]int) map[string]int {
	out := make(map[string]int)
	if edge.SubjectNew {
		for _, name := range countNames() {
			out[name] = 0
		}
		return out
	}
	if counts == nil {
		return nil
	}
	after, err := counts(ctx, edge.PK)
	if err != nil {
		log.Printf("WARNING: subject_counts read failed for %s %s: %v", edge.SubjectKind, edge.SubjectID, err)
		return nil
	}
	for _, name := range countNames() {
		n := after[name] - created[name]
		if n < 0 {
			n = 0
		}
		out[name] = n
	}
	return out
}

func countNames() []string {
	return []string{
		ddblib.RelationCountName(ddblib.RelationKindPerson),
		ddblib.RelationCountName(ddblib.RelationKindSession),
		ddblib.RelationCountName(ddblib.RelationKindAccount),
		ddblib.RelationCountName(ddblib.RelationKindRole),
		ddblib.RelationCountName(ddblib.RelationKindService),
		ddblib.RelationCountName(ddblib.RelationKindResource),
	}
}

func trigger(res *aggregator.Result, eventID string) *Record {
	record, ok := res.Records[eventID]
	if eventID == "" || !ok {
		return nil
	}
	trimmed := Trim(record)
	return &trimmed
}

// BuildSessionActivity builds one Session Activity event per session written.
func BuildSessionActivity(env Envelope, res *aggregator.Result) []Event {
	out := make([]Event, 0, len(res.Sessions))
	for _, written := range res.Sessions {
		sess := written.Session
		person := Person{Key: sess.PersonKey}
		if written.Person != nil {
			person.Email = written.Person.Email
			person.Label = written.Person.DisplayName
		}

		kept := min(len(written.Writes), MaxWrites)
		writes := make([]Record, 0, kept)
		for _, record := range written.Writes[:kept] {
			writes = append(writes, Trim(record))
		}

		var chainedInto []string
		for _, ref := range sess.ChainedSessionRefs {
			chainedInto = append(chainedInto, identity.SidFromRef(ref))
		}

		out = append(out, Event{DetailType: DetailTypeSessionActivity, Detail: &SessionActivity{
			Envelope: env,
			Session: SessionInfo{
				Sid:             written.Sid,
				Person:          person,
				Type:            sess.SessionType,
				AccountID:       sess.AccountID,
				RoleARN:         sess.RoleARN,
				RoleSessionName: sess.RoleSessionName,
				NewSession:      written.New,
				Origin: Origin{
					AssumedFromSession:       sidOf(sess.AssumedFromSession),
					AssumedFromRoleARN:       sess.AssumedFromRoleARN,
					AgentAuthorizedBySession: sidOf(sess.AgentAuthorizedBySession),
					MCPResource:              sess.MCPResource,
					LoginGrantedBySession:    sidOf(sess.LoginGrantedBySession),
					SessionTags:              sess.SessionTags,
					HasSessionPolicy:         sess.HasSessionPolicy,
				},
			},
			Activity: Activity{
				Start:              sess.StartTime,
				End:                sess.EndTime,
				EventsCount:        sess.EventsCount,
				DeniedCount:        sess.DeniedEventCount,
				ServiceDrivenCount: sess.ServiceDrivenEventCount,
				ClickOpsCount:      sess.ClickOpsEventCount,
				EventCounts:        sess.EventCounts,
				DeniedEventCounts:  sess.DeniedEventCounts,
				SourceIPs:          sess.SourceIPs,
				Clients:            sess.Clients,
				ChainedInto:        chainedInto,
				WriteCount:         len(written.Writes),
				Writes:             writes,
				WritesTruncated:    len(written.Writes) - kept,
			},
		}})
	}
	return out
}

func sidOf(ref string) string {
	if ref == "" {
		return ""
	}
	return identity.SidFromRef(ref)
}
