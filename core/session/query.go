package session

import (
	"context"

	"github.com/engseclabs/trailtool/core/models"
	"github.com/engseclabs/trailtool/core/store"
)

// ListSessions returns sessions for a user (email or person key), optionally
// filtered. The returned person keys tell the caller how many identities the
// user value matched — one email can map to several (offboard/rehire, pre/post
// Identity Center adoption).
func ListSessions(ctx context.Context, s *store.Store, customerID, user string, filter store.SessionFilter) ([]models.Session, []string, error) {
	return s.ListSessions(ctx, customerID, user, filter)
}

// GetSessionByRef returns a single session by its stable ref ("person_key|sk").
func GetSessionByRef(ctx context.Context, s *store.Store, customerID, ref string) (*models.Session, error) {
	return s.GetSessionByRef(ctx, customerID, ref)
}
