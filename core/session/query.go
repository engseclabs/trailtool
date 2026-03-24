package session

import (
	"context"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/store"
)

// ListSessions returns sessions for a user, optionally filtered
func ListSessions(ctx context.Context, s *store.Store, customerID, email string, filter store.SessionFilter) ([]models.SessionAggregated, error) {
	return s.ListSessions(ctx, customerID, email, filter)
}

// GetSession returns a single session by its composite sort key (startTime#sessionID)
func GetSession(ctx context.Context, s *store.Store, customerID, sessionStart string) (*models.SessionAggregated, error) {
	return s.GetSession(ctx, customerID, sessionStart)
}
