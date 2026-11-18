// Package verification proves a user controls an email address or phone number
// by sending a one-time code, both to verify the address on file and to change
// the account's email. Codes go out through a notifier.Sender.
package verification

import (
	"cmp"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service proves a user controls an email address or phone number, by a code
// sent to it.
type Service struct {
	pool        *pgxpool.Pool
	q           *dbgen.Queries
	sender      notifier.Sender
	ttl         time.Duration
	plan        entitlements.PlanGate     // gates SMS codes, which cost per message, by plan
	deliverable func(channel string) bool // whether a channel can deliver a code
}

// Requester is who asked, for the audit trail: the actor, and the organization
// their session is in (nil before they belong to one).
type Requester struct {
	audit.Actor
	OrganizationID *uuid.UUID
}

// event is an audit event of action on userID's account, on the chain of the
// organization r's session is in, or with none on a platform chain.
func (r Requester) event(action string, userID uuid.UUID, metadata map[string]any) audit.Event {
	return r.EventIn(r.OrganizationID, action, "user", userID, metadata)
}

// NewService returns the verification service, sending codes good for ttl
// (zero: 10 minutes) through sender. plan gates SMS codes; deliverable says
// whether a channel can deliver one (notifier.Router.Configured).
func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration, plan entitlements.PlanGate, deliverable func(channel string) bool) (*Service, error) {
	switch {
	case sender == nil:
		return nil, errors.New("verification: the service needs a sender")
	case plan == nil:
		return nil, errors.New("verification: the service needs a plan gate")
	case deliverable == nil:
		return nil, errors.New("verification: the service needs a delivery check")
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: cmp.Or(ttl, 10*time.Minute), plan: plan, deliverable: deliverable}, nil
}
