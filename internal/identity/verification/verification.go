// Package verification proves a user controls an email address or phone number
// by sending a one-time code, both to verify the address on file and to change
// the account's email. Codes go out through a notifier.Sender.
package verification

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service proves a user controls an email address or phone number, by a code
// sent to it.
type Service struct {
	pool        *pgxpool.Pool
	q           *dbgen.Queries
	sender      notifier.Sender
	ttl         time.Duration
	plan        entitlements.PlanGate     // gates SMS codes by plan (nil = no gate)
	deliverable func(channel string) bool // whether a channel can deliver (nil = assume it can)
}

// SetPlan wires the plan gate for SMS codes, which cost per message.
func (s *Service) SetPlan(p entitlements.PlanGate) { s.plan = p }

// SetDeliveryCheck wires the check that a channel can deliver a code
// (notifier.Router.Configured).
func (s *Service) SetDeliveryCheck(deliverable func(channel string) bool) {
	s.deliverable = deliverable
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

// NewService returns the verification service.
func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl}
}
