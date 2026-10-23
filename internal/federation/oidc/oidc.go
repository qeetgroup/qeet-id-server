// Package oidc implements Qeet's OpenID Connect provider role: the OAuth2/OIDC
// grants (authorization_code+PKCE, refresh, client_credentials, token-exchange,
// device, CIBA) plus discovery, JWKS, and userinfo endpoints.
package oidc

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Service is the OpenID Connect provider: clients, grants and tokens.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
	// notifier delivers the CIBA async consent prompt (nil = no notification;
	// the user must know to check pending requests themselves). See ciba.go.
	notifier Notifier
	// limits gates application (relying-party) registration by plan (nil = off).
	limits PlanLimiter
	// grantMaxAge ends a grant that long after it starts however often it is
	// renewed, where its organisation sets no maximum session age of its own.
	grantMaxAge time.Duration
	// addresses is the organisations' address rules (nil = no rules). See
	// address.go.
	addresses AddressPolicy
	// lockout bounds wrong application secrets. See client_lockout.go.
	lockout ClientLockout
	// logoutClient sends back-channel sign-out notices under logoutEgress
	// (the SSRF guard); nil sends none. See logout.go.
	logoutClient *http.Client
	logoutEgress *egress.Policy
	// exchangeMaxDepth bounds a chain of token exchanges (config
	// TOKEN_EXCHANGE_MAX_DEPTH).
	exchangeMaxDepth int
	// agentStatus returns an AI agent's lifecycle status, so introspection
	// reports a suspended agent's tokens inactive (nil: not checked).
	agentStatus func(ctx context.Context, agentID uuid.UUID) (string, error)
}

// SetAgentStatus wires the agent lifecycle lookup introspection consults.
func (s *Service) SetAgentStatus(f func(ctx context.Context, agentID uuid.UUID) (string, error)) {
	s.agentStatus = f
}

// NewService returns the OIDC provider service.
func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer, grantMaxAge: 30 * 24 * time.Hour, lockout: DefaultClientLockout(), exchangeMaxDepth: 2}
}

// SetTokenExchangeMaxDepth sets how many exchanges deep a token may be
// exchanged again (at least 1).
func (s *Service) SetTokenExchangeMaxDepth(n int) {
	if n < 1 {
		n = 1
	}
	s.exchangeMaxDepth = n
}

// SetGrantMaxAge sets how long an application's grant lasts however often it is
// renewed, where its organisation sets no maximum session age (config
// SESSION_MAX_AGE).
func (s *Service) SetGrantMaxAge(d time.Duration) { s.grantMaxAge = d }

// optionalUUID stores uuid.Nil as SQL NULL.
func optionalUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil}
}

// optionalString is s for a nullable column, nil for "".
func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// =====================================================================
// OAuth 2.0 token revocation (RFC 7009) & introspection (RFC 7662)
// =====================================================================

// =====================================================================
// OAuth grant administration (live OIDC refresh-token grants)
// =====================================================================
