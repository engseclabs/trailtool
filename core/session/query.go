package session

import (
	"context"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/store"
)

// ListSessions returns sessions for a user, optionally filtered by days
func ListSessions(ctx context.Context, s *store.Store, customerID, email string, days int) ([]models.SessionAggregated, error) {
	return s.ListSessions(ctx, customerID, email, days)
}

// GetSession returns a single session by start time
func GetSession(ctx context.Context, s *store.Store, customerID, startTime string) (*models.SessionAggregated, error) {
	return s.GetSession(ctx, customerID, startTime)
}
