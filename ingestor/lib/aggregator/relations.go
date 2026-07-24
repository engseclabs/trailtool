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

type relationCollector map[string]types.DynamoDBRelation

func (c relationCollector) observePair(customerID string, a, b relationEndpoint, observedAt string) {
	if a.id == "" || b.id == "" || a.kind == b.kind {
		return
	}
	c.observe(ddblib.NewRelation(customerID, a.kind, a.id, b.kind, b.id, observedAt))
	c.observe(ddblib.NewRelation(customerID, b.kind, b.id, a.kind, a.id, observedAt))
}

func (c relationCollector) observe(relation types.DynamoDBRelation) {
	key := relation.PK + "\x00" + relation.SK
	if existing, ok := c[key]; ok {
		if relation.FirstSeen < existing.FirstSeen {
			existing.FirstSeen = relation.FirstSeen
		}
		if relation.LastSeen > existing.LastSeen {
			existing.LastSeen = relation.LastSeen
		}
		c[key] = existing
		return
	}
	c[key] = relation
}

func (c relationCollector) edges() []types.DynamoDBRelation {
	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	edges := make([]types.DynamoDBRelation, 0, len(keys))
	for _, key := range keys {
		edges = append(edges, c[key])
	}
	return edges
}

func (c relationCollector) replaceID(kind, oldID, newID string) {
	if oldID == "" || newID == "" || oldID == newID {
		return
	}
	edges := c.edges()
	clear(c)
	for _, edge := range edges {
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
		c.observe(rebuilt)
	}
}

func recordEventRelations(
	collector relationCollector,
	customerID string,
	observedAt string,
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
			collector.observePair(customerID, core[i], core[j], observedAt)
		}
	}
	for _, resourceID := range resourceIDs {
		resource := relationEndpoint{kind: ddblib.RelationKindResource, id: resourceID}
		for _, endpoint := range core {
			collector.observePair(customerID, resource, endpoint, observedAt)
		}
	}
}
