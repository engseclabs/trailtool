package aggregator

import (
	"sort"

	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

type relationEndpoint struct {
	kind string
	id   string
}

// collectedRelation is one batch edge plus the eventID of its earliest
// observation, which becomes the trigger of a Relation Created event. The
// trigger stays in memory and is never persisted.
type collectedRelation struct {
	types.DynamoDBRelation
	TriggerEventID string
}

type relationCollector map[string]collectedRelation

func (c relationCollector) observePair(customerID string, a, b relationEndpoint, observedAt, eventID string) {
	if a.id == "" || b.id == "" || a.kind == b.kind {
		return
	}
	c.observe(ddblib.NewRelation(customerID, a.kind, a.id, b.kind, b.id, observedAt), eventID)
	c.observe(ddblib.NewRelation(customerID, b.kind, b.id, a.kind, a.id, observedAt), eventID)
}

func (c relationCollector) observe(relation types.DynamoDBRelation, eventID string) {
	key := relation.PK + "\x00" + relation.SK
	if existing, ok := c[key]; ok {
		if relation.FirstSeen < existing.FirstSeen {
			existing.FirstSeen = relation.FirstSeen
			existing.TriggerEventID = eventID
		}
		if relation.LastSeen > existing.LastSeen {
			existing.LastSeen = relation.LastSeen
		}
		c[key] = existing
		return
	}
	c[key] = collectedRelation{DynamoDBRelation: relation, TriggerEventID: eventID}
}

func (c relationCollector) sortedKeys() []string {
	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (c relationCollector) edges() []types.DynamoDBRelation {
	keys := c.sortedKeys()
	edges := make([]types.DynamoDBRelation, 0, len(keys))
	for _, key := range keys {
		edges = append(edges, c[key].DynamoDBRelation)
	}
	return edges
}

func (c relationCollector) replaceID(kind, oldID, newID string) {
	// TODO: Reconcile already-persisted oldID edges and decrement their
	// increment-only summaries when a cross-batch window fold rewrites a
	// session ref. A full re-ingest rebuilds both edges and summaries exactly.
	if oldID == "" || newID == "" || oldID == newID {
		return
	}
	keys := c.sortedKeys()
	collected := make([]collectedRelation, 0, len(keys))
	for _, key := range keys {
		collected = append(collected, c[key])
	}
	clear(c)
	for _, edge := range collected {
		if edge.SubjectKind == kind && edge.SubjectID == oldID {
			edge.SubjectID = newID
		}
		if edge.RelatedKind == kind && edge.RelatedID == oldID {
			edge.RelatedID = newID
		}
		rebuilt := ddblib.NewRelation(
			edge.CustomerID,
			edge.SubjectKind,
			edge.SubjectID,
			edge.RelatedKind,
			edge.RelatedID,
			edge.FirstSeen,
		)
		rebuilt.LastSeen = edge.LastSeen
		c.observe(rebuilt, edge.TriggerEventID)
	}
}

func recordEventRelations(
	collector relationCollector,
	customerID string,
	observedAt string,
	eventID string,
	personKey string,
	sessionRef string,
	accountID string,
	roleARN string,
	eventSource string,
	resourceIDs []string,
) {
	core := []relationEndpoint{
		{kind: ddblib.RelationKindPerson, id: personKey},
		{kind: ddblib.RelationKindSession, id: sessionRef},
		{kind: ddblib.RelationKindAccount, id: accountID},
		{kind: ddblib.RelationKindRole, id: roleARN},
		{kind: ddblib.RelationKindService, id: eventSource},
	}

	for i := range core {
		for j := i + 1; j < len(core); j++ {
			collector.observePair(customerID, core[i], core[j], observedAt, eventID)
		}
	}
	for _, resourceID := range resourceIDs {
		resource := relationEndpoint{kind: ddblib.RelationKindResource, id: resourceID}
		for _, endpoint := range core {
			collector.observePair(customerID, resource, endpoint, observedAt, eventID)
		}
	}
}
