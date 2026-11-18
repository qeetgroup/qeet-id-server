package oidc

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// authedClient is the client a request identified itself as. For a public
// client that identity is only claimed: its client_id is in every sign-in link
// and it has no secret, so an endpoint that needs proof calls
// requireConfidential.
type authedClient struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	ClientID       string
	Type           string
	GrantTypes     []string
	Scopes         []string // the scopes it is registered for
}

// authenticateClient identifies the calling client: a confidential client must
// present its secret, a public one presents none. A wrong secret is audited
// against the client's organization. Unknown client ids are refused without an audit
// row, so an unauthenticated caller can't fill the audit trail.
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (authedClient, error) {
	row, err := s.q.GetClientForAuth(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authedClient{}, errs.ErrOIDCClientAuthFailed
	}
	if err != nil {
		return authedClient{}, err
	}
	c := authedClient{ID: row.ID, OrganizationID: row.OrganizationID, ClientID: clientID, Type: row.Type, GrantTypes: row.GrantTypes, Scopes: row.Scopes}
	if row.Type == "confidential" {
		// A locked-out application is refused before its secret is compared,
		// with the same answer as a wrong one.
		locked, err := s.clientLocked(ctx, row.ID)
		if err != nil {
			return authedClient{}, err
		}
		if locked {
			return authedClient{}, errs.ErrOIDCClientAuthFailed
		}
		if row.ClientSecretHash == nil || !password.VerifySecret(*row.ClientSecretHash, clientSecret) {
			s.clientAuthFailed(ctx, c)
			return authedClient{}, errs.ErrOIDCClientAuthFailed
		}
		if err := s.q.ClearClientAuthFailures(ctx, dbgen.ClearClientAuthFailuresParams{ClientRowID: row.ID, SourceNetwork: callerNetwork(ctx)}); err != nil {
			return authedClient{}, err
		}
	}
	return c, nil
}

// requireConfidential refuses a public client at an endpoint that relies on
// client authentication (introspection, token exchange, backchannel sign-in):
// for a public client, presenting its client_id proves nothing.
func (s *Service) requireConfidential(ctx context.Context, c authedClient) error {
	if c.Type == "confidential" {
		return nil
	}
	s.auditClientAuthFailure(ctx, c, "public_client")
	return errs.ErrOIDCClientAuthFailed
}

// auditClientAuthFailure records a refused client authentication. Best-effort:
// the refusal stands whether or not the row is written.
func (s *Service) auditClientAuthFailure(ctx context.Context, c authedClient, reason string) {
	_ = audit.RecordAlone(ctx, s.pool, audit.Actor{Type: "client", IP: httpx.ClientIPFromContext(ctx)}.Event(
		c.OrganizationID, "oidc.client_auth_failed", "oidc_client", c.ID, map[string]any{"client_id": c.ClientID, "reason": reason}))
}
