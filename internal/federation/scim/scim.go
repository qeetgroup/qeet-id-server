// Package scim implements SCIM 2.0 (RFC 7643/7644) provisioning, so IdPs such
// as Okta and Entra ID can push and deprovision users and groups. The protocol
// is served at /scim/v2 behind a per-organization bearer token managed under /v1.
// Provisioned users are ordinary organization users tagged provisioned_via='scim'.
package scim

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

const (
	tokenPrefix      = "qf_scim_" // #nosec G101 -- token prefix, not a secret
	provisionedScim  = "scim"
	schemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaListResp   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimContentType  = "application/scim+json"
	defaultPageCount = 100
	maxPageCount     = 200
)

// Service manages SCIM tokens and provisioned users and groups. A nil signals
// announces no ended sessions; a nil gate leaves token rotation and SCIM
// requests ungated, and nil seats leaves group membership uncapped.
type Service struct {
	signals  *sessionsignal.Signaller
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	users    *user.Repository
	observer OperationObserver
	mapper   ProfileMapper
	gate     entitlements.PlanGate
	seats    entitlements.SeatGuard
}

// SetSeatGuard wires the seat limit on group membership (nil disables it).
func (s *Service) SetSeatGuard(g entitlements.SeatGuard) { s.seats = g }

// seatLimit returns the organization's seat cap, or -1 without a seat guard.
func (s *Service) seatLimit(ctx context.Context, organizationID uuid.UUID) (int, error) {
	if s.seats == nil {
		return -1, nil
	}
	return s.seats.SeatLimit(ctx, organizationID)
}

// withinSeats runs change in tx through the seat guard, if there is one.
func (s *Service) withinSeats(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, limit int, change func() error) error {
	if s.seats == nil {
		return change()
	}
	return s.seats.WithinSeats(ctx, tx, organizationID, limit, change)
}

// SetSessionSignals sets where the sessions ended by a SCIM suspension are
// announced.
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// NewService returns the SCIM service.
func NewService(pool *pgxpool.Pool, users *user.Repository) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), users: users}
}

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g entitlements.PlanGate) { s.gate = g }

// planIncludesSCIM reports whether the organization's plan includes SCIM; with no
// gate set, every plan does.
func (s *Service) planIncludesSCIM(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	if s.gate == nil {
		return true, nil
	}
	return s.gate.FeatureAllowed(ctx, organizationID, "scim")
}
