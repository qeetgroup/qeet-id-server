// Package principal manages OAuth-style service principals — non-human
// callers that authenticate via client_credentials grant and receive a
// short-lived service JWT scoped to a single organization.
package principal

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Service manages the service principals.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
}

// NewService returns the service-principal Service.
func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer}
}

// Principal is a service principal, without its secret. LastUsedAt is when it
// was last issued a token, to the minute; PreviousSecretExpiresAt, when the
// secret it replaced at its last rotation stops working.
type Principal struct {
	ID                      uuid.UUID  `json:"id"`
	OrganizationID          uuid.UUID  `json:"organization_id"`
	Name                    string     `json:"name"`
	Description             string     `json:"description"`
	Scopes                  []string   `json:"scopes"`
	DisabledAt              *time.Time `json:"disabled_at"`
	LastUsedAt              *time.Time `json:"last_used_at"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
}

// CreateInput is what Create takes. OrganizationID is set from the caller's
// token; one sent in the body is ignored.
type CreateInput struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Scopes         []string  `json:"scopes"`
}

// Create adds a service principal, created by actor, and returns it with its
// plaintext secret, shown only now.
func (s *Service) Create(ctx context.Context, in CreateInput, actor audit.Actor) (*Principal, string, error) {
	if err := rbac.ValidateMachineScopes(in.Scopes); err != nil {
		return nil, "", err
	}
	raw, _, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateServicePrincipal(ctx, dbgen.CreateServicePrincipalParams{
		OrganizationID: in.OrganizationID,
		Name:           in.Name,
		Description:    in.Description,
		SecretHash:     password.HashSecret(raw),
		Scopes:         in.Scopes,
		CreatedBy:      actor.UserID,
	})
	if err != nil {
		return nil, "", err
	}
	p := &Principal{
		ID: row.ID, OrganizationID: row.OrganizationID, Name: row.Name, Description: row.Description,
		Scopes: row.Scopes, DisabledAt: row.DisabledAt, CreatedAt: row.CreatedAt,
	}
	if err := audit.Record(ctx, tx, actor.Event(p.OrganizationID, "service_principal.created", "service_principal", p.ID,
		map[string]any{"name": p.Name, "scopes": p.Scopes})); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return p, raw, nil
}

// List returns the organization's service principals.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Principal, error) {
	rows, err := s.q.ListServicePrincipals(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Principal, 0, len(rows))
	for _, row := range rows {
		p := Principal{
			ID: row.ID, OrganizationID: row.OrganizationID, Name: row.Name, Description: row.Description,
			Scopes: row.Scopes, DisabledAt: row.DisabledAt, LastUsedAt: row.LastUsedAt, CreatedAt: row.CreatedAt,
		}
		if until := row.PreviousSecretExpiresAt; until != nil && until.After(time.Now()) {
			p.PreviousSecretExpiresAt = until
		}
		out = append(out, p)
	}
	return out, nil
}

// PrincipalLive reports whether service principal id exists and isn't
// disabled.
func (s *Service) PrincipalLive(ctx context.Context, id uuid.UUID) (bool, error) {
	live, err := s.q.PrincipalLive(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return live, err
}

// Disable marks one of the organization's enabled service principals disabled,
// recorded as actor's.
func (s *Service) Disable(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	name, err := s.q.WithTx(tx).DisableServicePrincipal(ctx, dbgen.DisableServicePrincipalParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "service_principal.disabled", "service_principal", id,
		map[string]any{"name": name})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ClientCredentials authenticates service principal clientID by its secret
// at the client_credentials grant and mints its access token. known is false,
// with no error, when clientID names no principal of an active organization.
func (s *Service) ClientCredentials(ctx context.Context, clientID, clientSecret string) (*tokens.MachineToken, bool, error) {
	pid, err := uuid.Parse(clientID)
	if err != nil {
		return nil, false, nil //nolint:nilerr // an id that isn't a UUID names no principal
	}
	row, err := s.q.GetServicePrincipalForAuth(ctx, pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	// The secret first, so only its holder learns that it is disabled.
	if !password.VerifySecret(row.SecretHash, clientSecret) && !rotation.PreviousSecretWorks(row.PreviousSecretHash, row.PreviousSecretExpiresAt, clientSecret) {
		return nil, true, errs.ErrPrincipalInvalidCredentials
	}
	if row.DisabledAt != nil {
		return nil, true, errs.ErrPrincipalDisabled
	}
	if err := s.q.TouchServicePrincipal(ctx, dbgen.TouchServicePrincipalParams{ID: row.ID, OrganizationID: row.OrganizationID}); err != nil {
		slog.Warn("service principal last use not recorded", "err", err, "principal_id", row.ID)
	}
	tok, err := s.issuer.IssueMachineAccess(tokens.MachineAccess{Subject: row.ID, OrganizationID: row.OrganizationID, Scopes: row.Scopes})
	return tok, true, err
}
