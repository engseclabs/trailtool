package dynamodb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

func winSession(sk, start, end string, events int, version int64) *types.DynamoDBSession {
	return &types.DynamoDBSession{
		PK:          "test#iamuser#arn:aws:iam::111111111111:user/deploy-bot",
		SK:          sk,
		CustomerID:  "test",
		PersonKey:   "iamuser#arn:aws:iam::111111111111:user/deploy-bot",
		Anchor:      sk,
		SessionType: "cli",
		RoleID:      "AIDADEPLOYBOT1234567",
		StartTime:   start,
		EndTime:     end,
		EventsCount: events,
		Version:     version,
		EventCounts: map[string]int{"s3.amazonaws.com:ListBuckets": events},
	}
}

func TestFoldWindowsCreatesWhenNothingAdjacent(t *testing.T) {
	incoming := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:10:00Z", 2, 1)
	merged, expectedVersion, deletions := FoldWindows(nil, incoming, 30*time.Minute)
	if expectedVersion != 0 {
		t.Errorf("expectedVersion = %d, want 0 (fresh create)", expectedVersion)
	}
	if len(deletions) != 0 {
		t.Errorf("deletions = %v, want none", deletions)
	}
	if merged.SK != incoming.SK || merged.Version != 1 {
		t.Errorf("merged SK/version = %s/%d, want %s/1", merged.SK, merged.Version, incoming.SK)
	}
}

// §8.2(1): a run overlapping an existing win# session extends it — SK sticky,
// true bounds move.
func TestFoldWindowsExtendsStickySK(t *testing.T) {
	existing := []types.DynamoDBSession{
		*winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:20:00Z", 3, 4),
	}
	// A later batch delivers an EARLIER run (late file delivery): SK must stay,
	// start_time must move.
	incoming := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T09:45:00Z", "2026-07-15T09:45:00Z", "2026-07-15T09:55:00Z", 2, 1)

	merged, expectedVersion, deletions := FoldWindows(existing, incoming, 30*time.Minute)
	if expectedVersion != 4 {
		t.Errorf("expectedVersion = %d, want 4", expectedVersion)
	}
	if len(deletions) != 0 {
		t.Errorf("deletions = %v, want none", deletions)
	}
	if merged.SK != "win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z" {
		t.Errorf("SK = %q, want the first-written (sticky) key", merged.SK)
	}
	if merged.StartTime != "2026-07-15T09:45:00Z" || merged.EndTime != "2026-07-15T10:20:00Z" {
		t.Errorf("bounds = [%s, %s], want true bounds [09:45, 10:20]", merged.StartTime, merged.EndTime)
	}
	if merged.EventsCount != 5 {
		t.Errorf("EventsCount = %d, want 5", merged.EventsCount)
	}
	if merged.Version != 5 {
		t.Errorf("Version = %d, want 5 (bumped)", merged.Version)
	}
}

// §8.2(2): a run bridging two existing sessions folds them into the
// earliest-SK record and deletes the other.
func TestFoldWindowsBridgesTwoSessions(t *testing.T) {
	existing := []types.DynamoDBSession{
		*winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:50:00Z", "2026-07-15T10:50:00Z", "2026-07-15T11:00:00Z", 4, 2),
		*winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:10:00Z", 3, 1),
	}
	incoming := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:15:00Z", "2026-07-15T10:15:00Z", "2026-07-15T10:45:00Z", 2, 1)

	merged, expectedVersion, deletions := FoldWindows(existing, incoming, 30*time.Minute)
	if merged.SK != "win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z" {
		t.Errorf("SK = %q, want the earliest existing key", merged.SK)
	}
	if expectedVersion != 1 {
		t.Errorf("expectedVersion = %d, want 1 (the survivor's version)", expectedVersion)
	}
	if len(deletions) != 1 || deletions[0].SK != "win#AIDADEPLOYBOT1234567#2026-07-15T10:50:00Z" || deletions[0].Version != 2 {
		t.Errorf("deletions = %+v, want the 10:50 record at version 2", deletions)
	}
	if merged.EventsCount != 9 {
		t.Errorf("EventsCount = %d, want 9 (3+2+4)", merged.EventsCount)
	}
	if merged.StartTime != "2026-07-15T10:00:00Z" || merged.EndTime != "2026-07-15T11:00:00Z" {
		t.Errorf("bounds = [%s, %s], want [10:00, 11:00]", merged.StartTime, merged.EndTime)
	}
}

// Windows in different channels never fold — a browser bout and a CLI bout on
// the same key stay separate sessions.
func TestFoldWindowsChannelSeparation(t *testing.T) {
	web := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:10:00Z", 3, 1)
	web.SessionType = "web"
	incoming := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:05:00Z", "2026-07-15T10:05:00Z", "2026-07-15T10:15:00Z", 2, 1)

	merged, expectedVersion, deletions := FoldWindows([]types.DynamoDBSession{*web}, incoming, 30*time.Minute)
	if expectedVersion != 0 || len(deletions) != 0 {
		t.Errorf("expectedVersion=%d deletions=%v, want fresh create with no deletions", expectedVersion, deletions)
	}
	if merged.SK != incoming.SK {
		t.Errorf("SK = %q, want the incoming run's own key", merged.SK)
	}
}

// fakeStore is an in-memory SessionStore implementing the conditional-write
// semantics the windowed path relies on.
type fakeStore struct {
	items map[string]map[string]ddbtypes.AttributeValue // "pk|sk" -> item
	// onQuery runs after each Query returns — the hook window where a
	// concurrent writer can sneak in.
	onQuery func(s *fakeStore)
}

func newFakeStore() *fakeStore {
	return &fakeStore{items: make(map[string]map[string]ddbtypes.AttributeValue)}
}

func itemKey(av map[string]ddbtypes.AttributeValue) string {
	pk := av["pk"].(*ddbtypes.AttributeValueMemberS).Value
	sk := av["sk"].(*ddbtypes.AttributeValueMemberS).Value
	return pk + "|" + sk
}

func itemVersion(item map[string]ddbtypes.AttributeValue) string {
	if v, ok := item["version"].(*ddbtypes.AttributeValueMemberN); ok {
		return v.Value
	}
	return ""
}

func (s *fakeStore) GetItem(_ context.Context, params *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	item := s.items[itemKey(params.Key)]
	return &dynamodb.GetItemOutput{Item: item}, nil
}

func (s *fakeStore) Query(_ context.Context, params *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	vals := params.ExpressionAttributeValues
	pk := vals[":pk"].(*ddbtypes.AttributeValueMemberS).Value
	lo := vals[":lo"].(*ddbtypes.AttributeValueMemberS).Value
	hi := vals[":hi"].(*ddbtypes.AttributeValueMemberS).Value
	out := &dynamodb.QueryOutput{}
	for key, item := range s.items {
		itemPK, itemSK, _ := strings.Cut(key, "|")
		if itemPK == pk && itemSK >= lo && itemSK <= hi {
			out.Items = append(out.Items, item)
		}
	}
	if s.onQuery != nil {
		s.onQuery(s)
	}
	return out, nil
}

func (s *fakeStore) checkCondition(condition *string, vals map[string]ddbtypes.AttributeValue, key string) error {
	if condition == nil {
		return nil
	}
	existing, exists := s.items[key]
	switch {
	case *condition == "attribute_not_exists(pk)":
		if exists {
			return &ddbtypes.ConditionalCheckFailedException{}
		}
	case *condition == "version = :expected":
		expected := vals[":expected"].(*ddbtypes.AttributeValueMemberN).Value
		if !exists || itemVersion(existing) != expected {
			return &ddbtypes.ConditionalCheckFailedException{}
		}
	}
	return nil
}

func (s *fakeStore) PutItem(_ context.Context, params *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	key := itemKey(params.Item)
	if err := s.checkCondition(params.ConditionExpression, params.ExpressionAttributeValues, key); err != nil {
		return nil, err
	}
	s.items[key] = params.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (s *fakeStore) TransactWriteItems(_ context.Context, params *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	// Check every condition first — all-or-nothing.
	for _, tw := range params.TransactItems {
		if tw.Put != nil {
			if err := s.checkCondition(tw.Put.ConditionExpression, tw.Put.ExpressionAttributeValues, itemKey(tw.Put.Item)); err != nil {
				code := "ConditionalCheckFailed"
				return nil, &ddbtypes.TransactionCanceledException{
					CancellationReasons: []ddbtypes.CancellationReason{{Code: &code}},
				}
			}
		}
		if tw.Delete != nil {
			if err := s.checkCondition(tw.Delete.ConditionExpression, tw.Delete.ExpressionAttributeValues, itemKey(tw.Delete.Key)); err != nil {
				code := "ConditionalCheckFailed"
				return nil, &ddbtypes.TransactionCanceledException{
					CancellationReasons: []ddbtypes.CancellationReason{{Code: &code}},
				}
			}
		}
	}
	for _, tw := range params.TransactItems {
		if tw.Put != nil {
			s.items[itemKey(tw.Put.Item)] = tw.Put.Item
		}
		if tw.Delete != nil {
			delete(s.items, itemKey(tw.Delete.Key))
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (s *fakeStore) session(t *testing.T, key string) *types.DynamoDBSession {
	t.Helper()
	item, ok := s.items[key]
	if !ok {
		keys := make([]string, 0, len(s.items))
		for k := range s.items {
			keys = append(keys, k)
		}
		t.Fatalf("item %q not in store; have %v", key, keys)
	}
	var sess types.DynamoDBSession
	if err := attributevalue.UnmarshalMap(item, &sess); err != nil {
		t.Fatalf("unmarshal %q: %v", key, err)
	}
	return &sess
}

// fakeLinkGetter is a scripted BatchGetItem client: it returns each queued
// response in order, letting a test simulate DynamoDB returning some items plus
// UnprocessedKeys on the first call and the rest on the next.
type fakeLinkGetter struct {
	table     string
	responses []*dynamodb.BatchGetItemOutput
	calls     int
}

func (f *fakeLinkGetter) BatchGetItem(_ context.Context, _ *dynamodb.BatchGetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	i := f.calls
	f.calls++
	if i < len(f.responses) {
		return f.responses[i], nil
	}
	return &dynamodb.BatchGetItemOutput{}, nil
}

func linkItem(t *testing.T, pk string) map[string]ddbtypes.AttributeValue {
	t.Helper()
	item, err := attributevalue.MarshalMap(&types.DynamoDBIdentityLink{PK: pk, PersonKey: "iamuser#" + pk})
	if err != nil {
		t.Fatalf("marshal link %q: %v", pk, err)
	}
	return item
}

// A BatchGetItem that returns UnprocessedKeys must be retried until drained;
// records from the retried keys must still land in the result.
func TestBatchGetIdentityLinksRetriesUnprocessedKeys(t *testing.T) {
	const table = "links"
	pkA, pkB := "cred#AAA", "cred#BBB"

	getter := &fakeLinkGetter{
		table: table,
		responses: []*dynamodb.BatchGetItemOutput{
			// First call: return A, defer B as unprocessed.
			{
				Responses: map[string][]map[string]ddbtypes.AttributeValue{
					table: {linkItem(t, pkA)},
				},
				UnprocessedKeys: map[string]ddbtypes.KeysAndAttributes{
					table: {Keys: []map[string]ddbtypes.AttributeValue{
						{"pk": &ddbtypes.AttributeValueMemberS{Value: pkB}},
					}},
				},
			},
			// Second call (the retry): return B, nothing unprocessed.
			{
				Responses: map[string][]map[string]ddbtypes.AttributeValue{
					table: {linkItem(t, pkB)},
				},
			},
		},
	}

	result, err := BatchGetIdentityLinks(context.Background(), getter, table, []string{pkA, pkB})
	if err != nil {
		t.Fatalf("BatchGetIdentityLinks: %v", err)
	}
	if getter.calls != 2 {
		t.Errorf("BatchGetItem called %d times, want 2 (initial + retry)", getter.calls)
	}
	if len(result) != 2 {
		t.Fatalf("result has %d links, want 2: %v", len(result), result)
	}
	if result[pkA] == nil || result[pkB] == nil {
		t.Errorf("missing a link: got %v, want both %s and %s", result, pkA, pkB)
	}
}

// A denied ResourceAccess carries policy fields (PolicyARN/PolicyType/
// ErrorMessage); those must survive a cross-batch merge, with counts summed.
func TestMergeResourceAccessesPreservesPolicyFields(t *testing.T) {
	denied := types.ResourceAccess{
		Resource:     "s3:bucket:secret",
		Service:      "s3.amazonaws.com",
		EventName:    "GetObject",
		Count:        1,
		PolicyARN:    "arn:aws:iam::111111111111:policy/DenyAll",
		PolicyType:   "SCP",
		ErrorMessage: "explicit deny in SCP",
	}
	// Second batch: same denied access seen again (empty ErrorMessage this time).
	again := denied
	again.ErrorMessage = ""

	merged := MergeResourceAccesses([]types.ResourceAccess{denied}, []types.ResourceAccess{again})
	if len(merged) != 1 {
		t.Fatalf("merged has %d entries, want 1 (same key): %+v", len(merged), merged)
	}
	got := merged[0]
	if got.Count != 2 {
		t.Errorf("Count = %d, want 2 (summed)", got.Count)
	}
	if got.PolicyARN != denied.PolicyARN {
		t.Errorf("PolicyARN = %q, want %q", got.PolicyARN, denied.PolicyARN)
	}
	if got.PolicyType != denied.PolicyType {
		t.Errorf("PolicyType = %q, want %q", got.PolicyType, denied.PolicyType)
	}
	if got.ErrorMessage != denied.ErrorMessage {
		t.Errorf("ErrorMessage = %q, want %q (first non-empty)", got.ErrorMessage, denied.ErrorMessage)
	}
}

func TestWriteWindowedSessionCreateThenExtend(t *testing.T) {
	store := newFakeStore()
	gap := 30 * time.Minute

	run1 := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:10:00Z", 2, 1)
	if err := WriteWindowedSession(context.Background(), store, "sessions", run1, gap); err != nil {
		t.Fatalf("create write: %v", err)
	}
	if len(store.items) != 1 {
		t.Fatalf("store has %d items, want 1", len(store.items))
	}

	// An adjacent run in the next batch extends the same item under the sticky SK.
	run2 := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:25:00Z", "2026-07-15T10:25:00Z", "2026-07-15T10:35:00Z", 3, 1)
	if err := WriteWindowedSession(context.Background(), store, "sessions", run2, gap); err != nil {
		t.Fatalf("extend write: %v", err)
	}
	if len(store.items) != 1 {
		t.Fatalf("store has %d items after extend, want 1", len(store.items))
	}
	sess := store.session(t, run1.PK+"|"+run1.SK)
	if sess.EventsCount != 5 {
		t.Errorf("EventsCount = %d, want 5", sess.EventsCount)
	}
	if sess.EndTime != "2026-07-15T10:35:00Z" {
		t.Errorf("EndTime = %s, want 10:35", sess.EndTime)
	}
	if sess.Version != 2 {
		t.Errorf("Version = %d, want 2", sess.Version)
	}
}

func TestWriteWindowedSessionBridgeDeletesFolded(t *testing.T) {
	store := newFakeStore()
	gap := 30 * time.Minute

	early := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:10:00Z", 3, 1)
	late := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T11:20:00Z", "2026-07-15T11:20:00Z", "2026-07-15T11:30:00Z", 4, 1)
	for _, s := range []*types.DynamoDBSession{early, late} {
		if err := WriteWindowedSession(context.Background(), store, "sessions", s, gap); err != nil {
			t.Fatalf("seed write: %v", err)
		}
	}
	if len(store.items) != 2 {
		t.Fatalf("store has %d items after seeding, want 2", len(store.items))
	}

	bridge := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:30:00Z", "2026-07-15T10:30:00Z", "2026-07-15T11:00:00Z", 2, 1)
	if err := WriteWindowedSession(context.Background(), store, "sessions", bridge, gap); err != nil {
		t.Fatalf("bridge write: %v", err)
	}
	if len(store.items) != 1 {
		t.Fatalf("store has %d items after bridge, want 1 (folded)", len(store.items))
	}
	sess := store.session(t, early.PK+"|"+early.SK)
	if sess.EventsCount != 9 {
		t.Errorf("EventsCount = %d, want 9", sess.EventsCount)
	}
	if sess.StartTime != "2026-07-15T10:00:00Z" || sess.EndTime != "2026-07-15T11:30:00Z" {
		t.Errorf("bounds = [%s, %s], want [10:00, 11:30]", sess.StartTime, sess.EndTime)
	}
}

// §8.2(3): a conditional-write conflict re-reads and converges — the concurrent
// writer's events survive alongside ours.
func TestWriteWindowedSessionConflictRetriesAndConverges(t *testing.T) {
	store := newFakeStore()
	gap := 30 * time.Minute

	seed := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:10:00Z", 2, 1)
	if err := WriteWindowedSession(context.Background(), store, "sessions", seed, gap); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	// After our Query snapshot, a concurrent writer extends the same window
	// (bumping its version) exactly once.
	raced := false
	store.onQuery = func(s *fakeStore) {
		if raced {
			return
		}
		raced = true
		concurrent := winSession(seed.SK, "2026-07-15T10:00:00Z", "2026-07-15T10:12:00Z", 5, 2)
		item, err := attributevalue.MarshalMap(concurrent)
		if err != nil {
			t.Fatalf("marshal concurrent item: %v", err)
		}
		s.items[seed.PK+"|"+seed.SK] = item
	}

	ours := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:20:00Z", "2026-07-15T10:20:00Z", "2026-07-15T10:25:00Z", 3, 1)
	if err := WriteWindowedSession(context.Background(), store, "sessions", ours, gap); err != nil {
		t.Fatalf("racing write did not converge: %v", err)
	}

	sess := store.session(t, seed.PK+"|"+seed.SK)
	if sess.EventsCount != 8 {
		t.Errorf("EventsCount = %d, want 8 (concurrent writer's 5 + our 3)", sess.EventsCount)
	}
	if sess.Version != 3 {
		t.Errorf("Version = %d, want 3", sess.Version)
	}
	if sess.EndTime != "2026-07-15T10:25:00Z" {
		t.Errorf("EndTime = %s, want 10:25", sess.EndTime)
	}
}
