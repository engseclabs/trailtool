package aggregator

import (
	"context"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// makeSessionContext builds a SessionContext for a role session.
func makeSessionContext(creationDate, roleARN string) *types.SessionContext {
	sc := &types.SessionContext{}
	sc.Attributes.CreationDate = creationDate
	sc.SessionIssuer.ARN = roleARN
	sc.SessionIssuer.Type = "Role"
	return sc
}

// makeSessionContextWithSignIn builds a SessionContext carrying an aws:SignInSessionArn,
// as present on the MCP OAuth grant and on API calls made with the OAuth access token.
func makeSessionContextWithSignIn(creationDate, roleARN, signInSessionArn string) *types.SessionContext {
	sc := makeSessionContext(creationDate, roleARN)
	sc.SignInSessionArn = signInSessionArn
	return sc
}

// ref builds the expected session ref for an anchored session.
func ref(personKey, anchor, roleID string) string {
	return identity.SessionRef(personKey, identity.SessionSK(anchor, roleID))
}

// processForTest runs the aggregation and returns the in-memory sessions map
// (keyed by session ref "person_key|sk"). Empty Tables skip all DynamoDB I/O.
func processForTest(events []types.CloudTrailRecord) (map[string]*types.DynamoDBSession, error) {
	return processInternal(context.Background(), nil, Config{
		Tables:    Tables{},
		Namespace: "test",
	}, events)
}

func sessionKeys(m map[string]*types.DynamoDBSession) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
