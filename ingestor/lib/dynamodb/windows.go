// Windowed-fallback (win#) sessions — the only write path where time
// guesses and optimistic locking are load-bearing: query adjacent windows,
// extend/fold, write conditionally on version, retry on conflict.
package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// windowDeletion names a win# record folded into another and slated for a
// version-conditional delete.
type windowDeletion struct {
	SK      string
	Version int64
}

// FoldWindows merges an incoming windowed run into the overlapping/adjacent
// existing win# sessions (same channel only). Pure function — the write path
// wraps it in optimistic-lock retries. Returns the surviving record (earliest
// SK, sticky, per §3.2), the version the write must be conditional on (0 =
// fresh create), and the records folded away.
func FoldWindows(existing []types.DynamoDBSession, incoming *types.DynamoDBSession, idleGap time.Duration) (*types.DynamoDBSession, int64, []windowDeletion) {
	var overlapping []types.DynamoDBSession
	for _, e := range existing {
		if e.SessionType == incoming.SessionType &&
			windowsMergeable(e.StartTime, e.EndTime, incoming.StartTime, incoming.EndTime, idleGap) {
			overlapping = append(overlapping, e)
		}
	}
	if len(overlapping) == 0 {
		out := *incoming
		out.Version = 1
		return &out, 0, nil
	}

	sort.Slice(overlapping, func(a, b int) bool { return overlapping[a].SK < overlapping[b].SK })
	target := overlapping[0]
	expectedVersion := target.Version
	merged := MergeSession(&target, incoming)
	var deletions []windowDeletion
	for i := 1; i < len(overlapping); i++ {
		merged = MergeSession(merged, &overlapping[i])
		deletions = append(deletions, windowDeletion{SK: overlapping[i].SK, Version: overlapping[i].Version})
	}
	merged.Version = expectedVersion + 1
	return merged, expectedVersion, deletions
}

// windowsMergeable reports whether two windowed runs belong to one session: the
// gap between them (if any) is at most idleGap.
func windowsMergeable(aStart, aEnd, bStart, bEnd string, idleGap time.Duration) bool {
	as, err1 := time.Parse(time.RFC3339, aStart)
	ae, err2 := time.Parse(time.RFC3339, aEnd)
	bs, err3 := time.Parse(time.RFC3339, bStart)
	be, err4 := time.Parse(time.RFC3339, bEnd)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return false
	}
	return !bs.After(ae.Add(idleGap)) && !as.After(be.Add(idleGap))
}

// WriteWindowedSession merges a windowed (win#) session into DynamoDB — the only
// write path where time guesses and optimistic locking are load-bearing (§3.2):
// fetch potentially-adjacent windows in one Query (±2×idleGap), extend/fold
// overlapping runs, write back conditionally on version, retry ≤3 on conflict.
// A fold that deletes records runs as one transaction so a concurrent writer can
// never observe (or double-merge) a partially applied fold.
func WriteWindowedSession(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession, idleGap time.Duration) error {
	_, err := WriteWindowedSessionResolved(ctx, ddbClient, tableName, session, idleGap)
	return err
}

// WriteWindowedSessionResolved writes a windowed session and returns the
// persisted survivor, whose sticky SK may differ from the incoming batch key.
func WriteWindowedSessionResolved(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession, idleGap time.Duration) (*types.DynamoDBSession, error) {
	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		existing, err := queryAdjacentWindows(ctx, ddbClient, tableName, session, idleGap)
		if err != nil {
			return nil, fmt.Errorf("query adjacent windows: %w", err)
		}
		merged, expectedVersion, deletions := FoldWindows(existing, session, idleGap)

		if len(deletions) == 0 {
			err = putWindowConditional(ctx, ddbClient, tableName, merged, expectedVersion)
		} else {
			err = transactFoldWindows(ctx, ddbClient, tableName, merged, expectedVersion, deletions)
		}
		if err == nil {
			return merged, nil
		}
		if !isVersionConflict(err) {
			return nil, err
		}
		lastErr = err // concurrent writer got there first — re-read and converge
	}
	return nil, fmt.Errorf("windowed session write did not converge after %d retries: %w", maxRetries, lastErr)
}

// transactFoldWindows applies a fold atomically: the merged survivor is written
// and the folded-away records deleted in one transaction, each guarded by the
// version read during the fold.
func transactFoldWindows(ctx context.Context, ddbClient SessionStore, tableName string, merged *types.DynamoDBSession, expectedVersion int64, deletions []windowDeletion) error {
	item, err := attributevalue.MarshalMap(merged)
	if err != nil {
		return fmt.Errorf("failed to marshal windowed session: %w", err)
	}
	put := &ddbtypes.Put{
		TableName: aws.String(tableName),
		Item:      item,
	}
	if expectedVersion == 0 {
		put.ConditionExpression = aws.String("attribute_not_exists(pk)")
	} else {
		put.ConditionExpression = aws.String("version = :expected")
		put.ExpressionAttributeValues = map[string]ddbtypes.AttributeValue{
			":expected": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", expectedVersion)},
		}
	}
	items := []ddbtypes.TransactWriteItem{{Put: put}}
	for _, d := range deletions {
		items = append(items, ddbtypes.TransactWriteItem{Delete: &ddbtypes.Delete{
			TableName: aws.String(tableName),
			Key: map[string]ddbtypes.AttributeValue{
				"pk": &ddbtypes.AttributeValueMemberS{Value: merged.PK},
				"sk": &ddbtypes.AttributeValueMemberS{Value: d.SK},
			},
			ConditionExpression: aws.String("version = :expected"),
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":expected": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", d.Version)},
			},
		}})
	}
	_, err = ddbClient.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	return err
}

// queryAdjacentWindows fetches win# sessions for the same person and roleID
// whose sticky start keys fall within ±2×idleGap of the incoming run.
func queryAdjacentWindows(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession, idleGap time.Duration) ([]types.DynamoDBSession, error) {
	start, err := time.Parse(time.RFC3339, session.StartTime)
	if err != nil {
		return nil, fmt.Errorf("unparsable session start %q: %w", session.StartTime, err)
	}
	end, err := time.Parse(time.RFC3339, session.EndTime)
	if err != nil {
		end = start
	}
	prefix := "win#" + session.RoleID + "#"
	lo := prefix + start.Add(-2*idleGap).UTC().Format(time.RFC3339)
	hi := prefix + end.Add(2*idleGap).UTC().Format(time.RFC3339)

	out, err := ddbClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(tableName),
		KeyConditionExpression: aws.String("pk = :pk AND sk BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":pk": &ddbtypes.AttributeValueMemberS{Value: session.PK},
			":lo": &ddbtypes.AttributeValueMemberS{Value: lo},
			":hi": &ddbtypes.AttributeValueMemberS{Value: hi},
		},
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]types.DynamoDBSession, 0, len(out.Items))
	for _, item := range out.Items {
		var s types.DynamoDBSession
		if err := attributevalue.UnmarshalMap(item, &s); err != nil {
			log.Printf("WARNING: failed to unmarshal windowed session: %v", err)
			continue
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

func putWindowConditional(ctx context.Context, ddbClient SessionStore, tableName string, session *types.DynamoDBSession, expectedVersion int64) error {
	item, err := attributevalue.MarshalMap(session)
	if err != nil {
		return fmt.Errorf("failed to marshal windowed session: %w", err)
	}
	input := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	}
	if expectedVersion == 0 {
		input.ConditionExpression = aws.String("attribute_not_exists(pk)")
	} else {
		input.ConditionExpression = aws.String("version = :expected")
		input.ExpressionAttributeValues = map[string]ddbtypes.AttributeValue{
			":expected": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", expectedVersion)},
		}
	}
	_, err = ddbClient.PutItem(ctx, input)
	return err
}

// isVersionConflict reports whether a write lost an optimistic-lock race: a
// plain conditional-check failure, or a transaction cancelled by one.
func isVersionConflict(err error) bool {
	var ccf *ddbtypes.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return true
	}
	var tc *ddbtypes.TransactionCanceledException
	if errors.As(err, &tc) {
		for _, reason := range tc.CancellationReasons {
			if reason.Code != nil && *reason.Code == "ConditionalCheckFailed" {
				return true
			}
		}
	}
	return false
}
