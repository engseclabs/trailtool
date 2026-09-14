// DynamoDB transaction-conflict detection and bounded backoff.
package dynamodb

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	transactionMaxAttempts = 6
	transactionBaseDelay   = 25 * time.Millisecond
	transactionMaxDelay    = 400 * time.Millisecond
)

// isTransactionConflict distinguishes transient item contention from a failed
// condition. A conditional failure requires fresh state; a transaction
// conflict only requires waiting for the in-flight transaction to finish.
func isTransactionConflict(err error) bool {
	var conflict *ddbtypes.TransactionConflictException
	if errors.As(err, &conflict) {
		return true
	}
	var cancelled *ddbtypes.TransactionCanceledException
	if !errors.As(err, &cancelled) {
		return false
	}
	for _, reason := range cancelled.CancellationReasons {
		if reason.Code != nil && *reason.Code == "TransactionConflict" {
			return true
		}
	}
	return false
}

// retryTransactionConflict retries an operation only when DynamoDB reports
// transient transaction contention. Callers must pass an operation that is
// safe to repeat unchanged.
func retryTransactionConflict(ctx context.Context, op func() error) error {
	var err error
	for attempt := 0; attempt < transactionMaxAttempts; attempt++ {
		if attempt > 0 {
			if err := waitForTransactionRetry(ctx, attempt); err != nil {
				return err
			}
		}
		err = op()
		if !isTransactionConflict(err) {
			return err
		}
	}
	return err
}

func waitForTransactionRetry(ctx context.Context, attempt int) error {
	delay := transactionBaseDelay << (attempt - 1)
	if delay > transactionMaxDelay {
		delay = transactionMaxDelay
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
