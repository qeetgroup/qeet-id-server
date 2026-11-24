package invite

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Seats counts an organization's seats and keeps them within its plan's: all
// a seat guard needs, so a process that only grants roles holds the seats
// without the rest of the invitation service. Service embeds it.
type Seats struct {
	q      *dbgen.Queries
	limits entitlements.PlanLimiter
}

// NewSeats returns the seats over pool, capped by limits.
func NewSeats(pool *pgxpool.Pool, limits entitlements.PlanLimiter) (*Seats, error) {
	if limits == nil {
		return nil, errors.New("invite: the seats need a plan limiter")
	}
	return &Seats{q: dbgen.New(pool), limits: limits}, nil
}

// CountSeats returns the organization's seats in use (members + pending invites) — the
// value the plan seat limit is checked against; also surfaced as usage in billing.
// A member is a person holding a role in the organization, directly or through a
// group; an account without one, such as a customer signing in, holds no seat.
func (s *Seats) CountSeats(ctx context.Context, organizationID uuid.UUID) (int, error) {
	n, err := s.q.CountSeats(ctx, organizationID)
	return int(n), err
}

// SeatLimit returns the organization's seat cap, negative for none. It reads on the
// pool, so callers ask before they open the transaction WithinSeats joins.
func (s *Seats) SeatLimit(ctx context.Context, organizationID uuid.UUID) (int, error) {
	return s.limits.Limit(ctx, organizationID, "seats")
}

// WithinSeats runs change in tx and refuses it with errs.ErrPlanLimit when it
// gives someone their first role in the organization, so a seat, and leaves more
// seats in use than limit, from SeatLimit. A person already holding a role
// takes no other seat. A negative limit checks nothing.
func (s *Seats) WithinSeats(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, limit int, change func() error) error {
	if limit < 0 {
		return change()
	}
	q := s.q.WithTx(tx)
	if err := q.LockSeats(ctx, organizationID); err != nil {
		return err
	}
	before, err := q.CountSeatHolders(ctx, organizationID)
	if err != nil {
		return err
	}
	if err := change(); err != nil {
		return err
	}
	after, err := q.CountSeatHolders(ctx, organizationID)
	if err != nil || after <= before {
		return err
	}
	pending, err := q.CountPendingInvites(ctx, organizationID)
	if err != nil {
		return err
	}
	if int(after+pending) > limit {
		return seatLimitReached(limit)
	}
	return nil
}

// seatLimitReached is the refusal of a change that needs a seat beyond limit.
func seatLimitReached(limit int) error {
	return errs.ErrPlanLimit.WithMetadata(map[string]any{"resource": "seats", "limit": limit})
}
