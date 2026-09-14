package dynamodb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func transactionCancelled(codes ...string) error {
	reasons := make([]ddbtypes.CancellationReason, 0, len(codes))
	for _, code := range codes {
		code := code
		reasons = append(reasons, ddbtypes.CancellationReason{Code: &code})
	}
	return &ddbtypes.TransactionCanceledException{CancellationReasons: reasons}
}

func TestIsTransactionConflict(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "direct conflict", err: &ddbtypes.TransactionConflictException{}, want: true},
		{name: "transaction cancellation", err: transactionCancelled("TransactionConflict"), want: true},
		{name: "conditional cancellation", err: transactionCancelled("ConditionalCheckFailed"), want: false},
		{name: "conditional check", err: &ddbtypes.ConditionalCheckFailedException{}, want: false},
		{name: "unrelated error", err: errors.New("boom"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isTransactionConflict(test.err); got != test.want {
				t.Fatalf("isTransactionConflict() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRetryTransactionConflictStopsOnSuccessOrOtherError(t *testing.T) {
	calls := 0
	err := retryTransactionConflict(context.Background(), func() error {
		calls++
		if calls < 3 {
			return &ddbtypes.TransactionConflictException{}
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("retry result = %v after %d calls, want success after 3", err, calls)
	}

	sentinel := errors.New("do not retry")
	calls = 0
	err = retryTransactionConflict(context.Background(), func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("non-conflict result = %v after %d calls, want sentinel after 1", err, calls)
	}
}

func TestRetryTransactionConflictHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := retryTransactionConflict(ctx, func() error {
		calls++
		cancel()
		return &ddbtypes.TransactionConflictException{}
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("retry result = %v after %d calls, want cancellation after 1", err, calls)
	}
}

type transactionConflictStore struct {
	*fakeStore
	remaining int
	writes    int
}

func (s *transactionConflictStore) conflict() bool {
	s.writes++
	if s.remaining == 0 {
		return false
	}
	s.remaining--
	return true
}

func (s *transactionConflictStore) PutItem(ctx context.Context, input *dynamodb.PutItemInput, options ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if s.conflict() {
		return nil, &ddbtypes.TransactionConflictException{}
	}
	return s.fakeStore.PutItem(ctx, input, options...)
}

func (s *transactionConflictStore) TransactWriteItems(ctx context.Context, input *dynamodb.TransactWriteItemsInput, options ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if s.conflict() {
		return nil, transactionCancelled("TransactionConflict")
	}
	return s.fakeStore.TransactWriteItems(ctx, input, options...)
}

func TestWriteWindowedSessionRecomputesAfterTransactionConflicts(t *testing.T) {
	base := newFakeStore()
	gap := 30 * time.Minute
	first := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:00:00Z", "2026-07-15T10:00:00Z", "2026-07-15T10:10:00Z", 2, 1)
	if _, err := WriteWindowedSessionResolved(context.Background(), base, "sessions", first, gap); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	store := &transactionConflictStore{fakeStore: base, remaining: 2}
	later := winSession("win#AIDADEPLOYBOT1234567#2026-07-15T10:25:00Z", "2026-07-15T10:25:00Z", "2026-07-15T10:35:00Z", 3, 1)
	if _, err := WriteWindowedSessionResolved(context.Background(), store, "sessions", later, gap); err != nil {
		t.Fatalf("extend through conflicts: %v", err)
	}
	if store.writes != 3 {
		t.Fatalf("writes = %d, want 3", store.writes)
	}
	got := store.session(t, first.PK+"|"+first.SK)
	if got.EventsCount != 5 {
		t.Fatalf("EventsCount = %d, want 5 without a duplicate merge", got.EventsCount)
	}
}
