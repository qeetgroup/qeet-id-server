package entitlements

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PlanGate reports whether a boolean feature is in an organization's plan.
// Satisfied by *Service; a package that gates a feature takes one (nil allows
// every feature).
type PlanGate interface {
	FeatureAllowed(ctx context.Context, organizationID uuid.UUID, feature string) (bool, error)
}

// PlanLimiter returns the cap an organization's plan puts on resource,
// negative for none. Satisfied by *Service.
type PlanLimiter interface {
	Limit(ctx context.Context, organizationID uuid.UUID, resource string) (int, error)
}

// SeatGuard keeps the people holding a role in an organization within its
// plan's seats; a direct role, a group carrying one and a directory-managed
// group each take one. Satisfied by *invite.Service.
type SeatGuard interface {
	// SeatLimit returns the organization's seat cap, negative for none; it
	// reads on the pool, so it is asked before the transaction.
	SeatLimit(ctx context.Context, organizationID uuid.UUID) (int, error)
	// WithinSeats runs change in tx and refuses it when it gives someone a
	// first role beyond limit.
	WithinSeats(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, limit int, change func() error) error
}
