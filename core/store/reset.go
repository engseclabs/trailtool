package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// IdentityLinksTableName and IngestedFilesTableName name ingestor-owned tables
// the read path never queries but reset must clear. RelationsTableName is
// declared in details.go. See ingestor/lib/ingest/ingest.go (TablesFromEnv) and
// template.yaml.
const (
	IdentityLinksTableName = "trailtool-identity-links"
	IngestedFilesTableName = "trailtool-ingested-files"
)

// DerivedTables lists every DynamoDB table that is a projection of the
// CloudTrail log: the six read-path tables plus relations, identity-links, and
// the ingested-files markers. Reset empties all of them so the projection can
// be rebuilt from the log. The markers must go with the rest — leaving them
// would make a subsequent replay skip every object (see
// docs/design/cloudtrail-replay.md §4).
func DerivedTables() []string {
	return []string{
		PeopleTableName,
		SessionsTableName,
		RolesTableName,
		ResourcesTableName,
		AccountsTableName,
		ServicesTableName,
		RelationsTableName,
		IdentityLinksTableName,
		IngestedFilesTableName,
	}
}

// TableReset reports how many items were deleted from one table, or why it was
// skipped. A missing table is not an error: reset onto a partially-deployed or
// already-empty stack should still succeed.
type TableReset struct {
	Table   string `json:"table"`
	Deleted int    `json:"deleted"`
	Skipped bool   `json:"skipped"` // table did not exist
}

// CountItems returns the approximate item count for each derived table, for the
// pre-reset confirmation prompt. It uses DescribeTable's ItemCount (updated by
// DynamoDB roughly every six hours) rather than a full Scan, so the number is an
// estimate and cheap. A missing table reports count 0 and Skipped=true.
func (s *Store) CountItems(ctx context.Context, tables []string) ([]TableReset, error) {
	out := make([]TableReset, 0, len(tables))
	for _, table := range tables {
		desc, err := s.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(table),
		})
		if err != nil {
			if isTableNotFound(err) {
				out = append(out, TableReset{Table: table, Skipped: true})
				continue
			}
			return nil, s.explainError(ctx, err, "describe table "+table)
		}
		count := 0
		if desc.Table != nil && desc.Table.ItemCount != nil {
			count = int(*desc.Table.ItemCount)
		}
		out = append(out, TableReset{Table: table, Deleted: count})
	}
	return out, nil
}

// ResetProgress reports reset progress as it happens: which table (1-based
// index of total), and how many items have been deleted from it so far. It is
// called from Reset's single goroutine, so implementations need not be
// concurrency-safe. done reports whether the table just finished.
type ResetProgress func(table string, tableIndex, totalTables, deleted int, done bool)

// Reset empties each named table by scanning its keys and batch-deleting every
// item, keeping the table and its GSIs intact so live ingestion resumes the
// moment reset finishes (docs/design/cloudtrail-replay.md §4). A missing table
// is skipped, not fatal. It returns a per-table deletion count. A nil progress
// callback is fine.
//
// Reset is destructive to the derived projection and recoverable only by
// replaying the log. The caller owns confirmation.
func (s *Store) Reset(ctx context.Context, tables []string, progress ResetProgress) ([]TableReset, error) {
	out := make([]TableReset, 0, len(tables))
	for i, table := range tables {
		keys, err := s.tableKeyAttributes(ctx, table)
		if err != nil {
			if isTableNotFound(err) {
				out = append(out, TableReset{Table: table, Skipped: true})
				continue
			}
			return nil, err
		}
		var tableProgress func(int)
		if progress != nil {
			tableProgress = func(deleted int) { progress(table, i+1, len(tables), deleted, false) }
		}
		deleted, err := s.truncateTable(ctx, table, keys, tableProgress)
		if err != nil {
			return nil, err
		}
		if progress != nil {
			progress(table, i+1, len(tables), deleted, true)
		}
		out = append(out, TableReset{Table: table, Deleted: deleted})
	}
	return out, nil
}

// tableKeyAttributes returns a table's primary-key attribute names (hash, and
// range if present) from its schema, so truncateTable can project only the keys
// it needs to delete each item — without hardcoding each table's key layout.
func (s *Store) tableKeyAttributes(ctx context.Context, table string) ([]string, error) {
	desc, err := s.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(table),
	})
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, k := range desc.Table.KeySchema {
		keys = append(keys, aws.ToString(k.AttributeName))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("table %s has no key schema", table)
	}
	return keys, nil
}

// truncateTable scans the table projecting only its key attributes and deletes
// every item in batches of 25 (the BatchWriteItem limit), retrying unprocessed
// items. It returns the number of items deleted. onProgress, if non-nil, is
// called with the running deleted count after each scan page.
func (s *Store) truncateTable(ctx context.Context, table string, keyAttrs []string, onProgress func(deleted int)) (int, error) {
	projection, names := keyProjection(keyAttrs)

	deleted := 0
	var lastKey map[string]types.AttributeValue
	for {
		page, err := s.client.Scan(ctx, &dynamodb.ScanInput{
			TableName:                aws.String(table),
			ProjectionExpression:     aws.String(projection),
			ExpressionAttributeNames: names,
			ExclusiveStartKey:        lastKey,
		})
		if err != nil {
			return deleted, s.explainError(ctx, err, "scan table "+table)
		}

		for _, batch := range chunkItems(page.Items, 25) {
			n, err := s.deleteBatch(ctx, table, batch, keyAttrs)
			if err != nil {
				return deleted, err
			}
			deleted += n
		}
		if onProgress != nil {
			onProgress(deleted)
		}

		if page.LastEvaluatedKey == nil {
			break
		}
		lastKey = page.LastEvaluatedKey
	}
	return deleted, nil
}

// deleteBatch deletes one batch (<=25 items) via BatchWriteItem, re-submitting
// any UnprocessedItems until the batch is drained. It returns the count deleted.
func (s *Store) deleteBatch(ctx context.Context, table string, items []map[string]types.AttributeValue, keyAttrs []string) (int, error) {
	requests := make([]types.WriteRequest, 0, len(items))
	for _, item := range items {
		requests = append(requests, types.WriteRequest{
			DeleteRequest: &types.DeleteRequest{Key: keyOnly(item, keyAttrs)},
		})
	}

	pending := map[string][]types.WriteRequest{table: requests}
	for attempt := 0; len(pending) > 0; attempt++ {
		result, err := s.client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
			RequestItems: pending,
		})
		if err != nil {
			return 0, s.explainError(ctx, err, "delete from "+table)
		}
		if len(result.UnprocessedItems) == 0 {
			break
		}
		// UnprocessedItems is a successful response with leftovers (throttling),
		// not an SDK-retried error. Back off before re-submitting so a throttled
		// table does not spin. Capped exponential; honors ctx cancellation.
		if err := sleepBackoff(ctx, attempt); err != nil {
			return 0, err
		}
		pending = result.UnprocessedItems
	}
	return len(items), nil
}

// keyProjection renders the key attributes as a projection expression with
// placeholder names, avoiding any collision with DynamoDB reserved words.
func keyProjection(keyAttrs []string) (string, map[string]string) {
	names := make(map[string]string, len(keyAttrs))
	parts := make([]string, 0, len(keyAttrs))
	for i, attr := range keyAttrs {
		ph := fmt.Sprintf("#k%d", i)
		names[ph] = attr
		parts = append(parts, ph)
	}
	proj := parts[0]
	for _, p := range parts[1:] {
		proj += ", " + p
	}
	return proj, names
}

// keyOnly projects an item down to just its key attributes for a delete request.
func keyOnly(item map[string]types.AttributeValue, keyAttrs []string) map[string]types.AttributeValue {
	key := make(map[string]types.AttributeValue, len(keyAttrs))
	for _, attr := range keyAttrs {
		if v, ok := item[attr]; ok {
			key[attr] = v
		}
	}
	return key
}

func chunkItems(items []map[string]types.AttributeValue, size int) [][]map[string]types.AttributeValue {
	if len(items) == 0 {
		return nil
	}
	var chunks [][]map[string]types.AttributeValue
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
}

func isTableNotFound(err error) bool {
	var rnf *types.ResourceNotFoundException
	return errors.As(err, &rnf)
}

// sleepBackoff waits before re-submitting throttled BatchWriteItem leftovers:
// capped exponential (50ms, 100ms, ... up to 2s), cancellable via ctx.
func sleepBackoff(ctx context.Context, attempt int) error {
	const maxDelay = 2 * time.Second
	delay := maxDelay
	if attempt < 6 { // 50ms<<6 = 3.2s already exceeds the cap; avoid shift overflow
		delay = 50 * time.Millisecond << attempt
		if delay > maxDelay {
			delay = maxDelay
		}
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
