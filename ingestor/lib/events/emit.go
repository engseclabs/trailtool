package events

import (
	"context"
	"encoding/json"
	"log"
	"math/rand/v2"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

const (
	// maxEntryBytes is EventBridge's limit for one entry and for one
	// PutEvents request as a whole.
	maxEntryBytes = 256 * 1024
	// maxBatchEntries is the PutEvents entry limit.
	maxBatchEntries = 10
	// timeEntryBytes is what EventBridge charges an entry's Time field.
	timeEntryBytes = 14

	emitMaxAttempts = 4
)

// emitBaseDelay is the first retry delay; tests set it to zero.
var emitBaseDelay = 100 * time.Millisecond

// Emit publishes events to the bus in PutEvents batches, retrying failed
// entries with backoff. Delivery is best-effort: anything still undelivered
// is logged as EMIT_FAILED and dropped. Emit never fails the caller.
func Emit(ctx context.Context, pub Publisher, busArn string, evs []Event) {
	if pub == nil || busArn == "" || len(evs) == 0 {
		return
	}

	failed := make(map[string]int)
	var entries []ebtypes.PutEventsRequestEntry
	for _, ev := range evs {
		entry, ok := buildEntry(busArn, ev)
		if !ok {
			failed[ev.DetailType]++
			continue
		}
		entries = append(entries, entry)
	}

	var lastErr error
	sent := 0
	for _, batch := range packBatches(entries) {
		undelivered, err := putWithRetry(ctx, pub, batch)
		if err != nil {
			lastErr = err
		}
		sent += len(batch) - len(undelivered)
		for _, entry := range undelivered {
			failed[aws.ToString(entry.DetailType)]++
		}
	}

	if len(failed) > 0 {
		log.Printf("EMIT_FAILED: sent=%d failed=%v bus=%s last_error=%v", sent, failed, busArn, lastErr)
		return
	}
	log.Printf("EMIT_OK: sent=%d bus=%s", sent, busArn)
}

// buildEntry serializes one event. A Session Activity event over the entry
// limit sheds writes until it fits; any other oversized event is dropped.
func buildEntry(busArn string, ev Event) (ebtypes.PutEventsRequestEntry, bool) {
	detail, err := json.Marshal(ev.Detail)
	if err != nil {
		log.Printf("WARNING: marshal %s: %v", ev.DetailType, err)
		return ebtypes.PutEventsRequestEntry{}, false
	}
	if activity, ok := ev.Detail.(*SessionActivity); ok {
		for entrySize(ev.DetailType, detail) > maxEntryBytes && len(activity.Activity.Writes) > 0 {
			activity.Activity.Writes = activity.Activity.Writes[:len(activity.Activity.Writes)-1]
			activity.Activity.WritesTruncated++
			if detail, err = json.Marshal(activity); err != nil {
				log.Printf("WARNING: marshal %s: %v", ev.DetailType, err)
				return ebtypes.PutEventsRequestEntry{}, false
			}
		}
	}
	if size := entrySize(ev.DetailType, detail); size > maxEntryBytes {
		log.Printf("WARNING: dropping %s of %d bytes, over the %d-byte EventBridge limit", ev.DetailType, size, maxEntryBytes)
		return ebtypes.PutEventsRequestEntry{}, false
	}
	return ebtypes.PutEventsRequestEntry{
		EventBusName: aws.String(busArn),
		Source:       aws.String(Source),
		DetailType:   aws.String(ev.DetailType),
		Detail:       aws.String(string(detail)),
	}, true
}

// entrySize follows EventBridge's entry-size accounting.
func entrySize(detailType string, detail []byte) int {
	return timeEntryBytes + len(Source) + len(detailType) + len(detail)
}

// packBatches groups entries under both PutEvents limits: entry count and
// total request size.
func packBatches(entries []ebtypes.PutEventsRequestEntry) [][]ebtypes.PutEventsRequestEntry {
	var batches [][]ebtypes.PutEventsRequestEntry
	var current []ebtypes.PutEventsRequestEntry
	currentBytes := 0
	for _, entry := range entries {
		size := entrySize(aws.ToString(entry.DetailType), []byte(aws.ToString(entry.Detail)))
		if len(current) == maxBatchEntries || (len(current) > 0 && currentBytes+size > maxEntryBytes) {
			batches = append(batches, current)
			current, currentBytes = nil, 0
		}
		current = append(current, entry)
		currentBytes += size
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

// putWithRetry sends one batch, resending only the entries EventBridge
// rejected. A whole-call error is final: the SDK has already retried the
// retryable ones, and the rest (access denied, a missing bus) will not heal.
// It returns the entries still undelivered after the last attempt.
func putWithRetry(ctx context.Context, pub Publisher, batch []ebtypes.PutEventsRequestEntry) ([]ebtypes.PutEventsRequestEntry, error) {
	pending := batch
	var lastErr error
	for attempt := 0; attempt < emitMaxAttempts && len(pending) > 0; attempt++ {
		if attempt > 0 {
			if err := waitForEmitRetry(ctx, attempt); err != nil {
				return pending, err
			}
		}
		out, err := pub.PutEvents(ctx, &eventbridge.PutEventsInput{Entries: pending})
		if err != nil {
			return pending, err
		}
		if out.FailedEntryCount == 0 {
			return nil, nil
		}
		// Result entries align with request entries; a failed one carries an
		// ErrorCode.
		var retry []ebtypes.PutEventsRequestEntry
		for i, result := range out.Entries {
			if result.ErrorCode != nil && i < len(pending) {
				retry = append(retry, pending[i])
				lastErr = errorFromEntry(result)
			}
		}
		pending = retry
	}
	return pending, lastErr
}

type entryError struct{ code, message string }

func (e entryError) Error() string { return e.code + ": " + e.message }

func errorFromEntry(result ebtypes.PutEventsResultEntry) error {
	return entryError{code: aws.ToString(result.ErrorCode), message: aws.ToString(result.ErrorMessage)}
}

func waitForEmitRetry(ctx context.Context, attempt int) error {
	delay := emitBaseDelay << (attempt - 1)
	if delay <= 0 {
		return ctx.Err()
	}
	delay = delay/2 + time.Duration(rand.Int64N(int64(delay)))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
