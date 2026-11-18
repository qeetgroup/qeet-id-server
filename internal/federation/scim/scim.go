// Package scim implements SCIM 2.0 (RFC 7643/7644) provisioning, so IdPs such
// as Okta and Entra ID can push and deprovision users and groups. The protocol
// is served at /scim/v2 behind a per-organization bearer token managed under /v1.
// Provisioned users are ordinary organization users tagged provisioned_via='scim'.
package scim

import (
	"context"
	"errors"

	"github.com/google/uuid"
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

// Service manages SCIM tokens and provisioned users and groups.
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

// Deps are what the SCIM service is built from; every one is required.
type Deps struct {
	Pool     *pgxpool.Pool
	Users    *user.Repository
	Signals  *sessionsignal.Signaller // announces the sessions a suspension ends
	Gate     entitlements.PlanGate    // whether the plan includes SCIM
	Seats    entitlements.SeatGuard   // the seat limit on group membership
	Mapper   ProfileMapper            // the attribute mappings provisioned users get
	Observer OperationObserver        // records each provisioning operation
}

// NewService returns the SCIM service built from d, or an error naming the
// dependency d lacks.
func NewService(d Deps) (*Service, error) {
	switch {
	case d.Pool == nil:
		return nil, errors.New("scim: missing Pool")
	case d.Users == nil:
		return nil, errors.New("scim: missing Users")
	case d.Signals == nil:
		return nil, errors.New("scim: missing Signals")
	case d.Gate == nil:
		return nil, errors.New("scim: missing Gate")
	case d.Seats == nil:
		return nil, errors.New("scim: missing Seats")
	case d.Mapper == nil:
		return nil, errors.New("scim: missing Mapper")
	case d.Observer == nil:
		return nil, errors.New("scim: missing Observer")
	}
	return &Service{
		signals: d.Signals, pool: d.Pool, q: dbgen.New(d.Pool), users: d.Users,
		observer: d.Observer, mapper: d.Mapper, gate: d.Gate, seats: d.Seats,
	}, nil
}

// planIncludesSCIM reports whether the organization's plan includes SCIM.
func (s *Service) planIncludesSCIM(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	return s.gate.FeatureAllowed(ctx, organizationID, "scim")
}
