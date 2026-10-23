package oidc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// mayIntrospect reports whether clientID may see an access token of its
// tenant: it is the application the token was issued to (client_id claim), or
// it serves one of the registered resources the token was issued for.
func (s *Service) mayIntrospect(ctx context.Context, tenantID uuid.UUID, clientID string, claims *tokens.Claims) (bool, error) {
	if claims.ClientID != "" && claims.ClientID == clientID {
		return true, nil
	}
	res := resourcesOf(claims.Audience, s.issuer.JWTAudience())
	if len(res) == 0 {
		return false, nil
	}
	return s.q.ResourceServedBy(ctx, dbgen.ResourceServedByParams{TenantID: tenantID, ClientID: &clientID, Identifiers: res})
}

// auditIntrospectionRefused records an application asking about a token it
// doesn't own (owner "" for a token issued to no application).
func (s *Service) auditIntrospectionRefused(ctx context.Context, tenantID uuid.UUID, caller, owner string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "client", Action: "oidc.introspection_refused",
		ResourceType: "oidc_client", IP: httpx.ClientIPFromContext(ctx),
		Metadata: map[string]any{"client_id": caller, "token_client_id": owner, "outcome": "inactive"},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

// RevokeToken implements RFC 7009 for refresh tokens: it ends the whole grant,
// every rotation included, and audits it. An access token is refused with
// unsupported_token_type because it can't be revoked. An unknown token, or
// another client's, is a no-op success (RFC 7009 §2.2).
func (s *Service) RevokeToken(ctx context.Context, clientID, clientSecret, token, hint string) error {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	if token == "" {
		return nil
	}
	// Whatever its audience: a token issued for a registered resource is an
	// access token too.
	if _, err := s.issuer.VerifyAccessAnyAudience(token); err == nil {
		return oauthErr("unsupported_token_type", "access tokens can't be revoked; they expire on their own")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ended, err := s.q.WithTx(tx).RevokeRefreshTokenGrant(ctx, dbgen.RevokeRefreshTokenGrantParams{
		TokenHash: tokens.HashRefresh(token),
		ClientID:  clientID,
	})
	if err != nil {
		return err
	}
	if len(ended) == 0 {
		return nil
	}
	first := ended[0]
	tenantID, userID := first.TenantID, first.UserID
	var grantID *uuid.UUID
	if first.GrantID.Valid {
		g := uuid.UUID(first.GrantID.Bytes)
		grantID = &g
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorUserID: &userID, ActorType: "client",
		Action: "oidc.grant_revoked", ResourceType: "oidc_grant", ResourceID: grantID,
		IP: httpx.ClientIPFromContext(ctx),
		Metadata: map[string]any{
			"client_id": client.ClientID, "tokens_revoked": len(ended), "via": "revocation_endpoint",
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Introspect implements RFC 7662. After client authentication it reports
// whether the token is active and, if so, its metadata. It recognises both our
// ES256 access tokens (verified statelessly) and stored OIDC refresh tokens.
// token_type_hint, when given, picks which check to run first/only.
func (s *Service) Introspect(ctx context.Context, clientID, clientSecret, token, hint string) (map[string]any, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if err := s.requireConfidential(ctx, client); err != nil {
		return nil, err
	}
	inactive := map[string]any{"active": false}
	if token == "" {
		return inactive, nil
	}

	// RFC 7662 §2.1: the token must have been issued to the calling client, or this
	// endpoint becomes a token oracle for other tenants. A mismatch returns
	// active: false, which reveals nothing.
	caller, err := s.q.GetClientName(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Access token (stateless JWT) — unless the hint says it's a refresh token.
	// Whatever its audience: a token issued for a resource is still ours.
	if hint != "refresh_token" {
		if claims, err := s.issuer.VerifyAccessAnyAudience(token); err == nil {
			if claims.TenantID != caller.TenantID {
				return inactive, nil
			}
			// Only the application the token was issued to, or the service a
			// registered resource it names says serves it, may see it.
			allowed, err := s.mayIntrospect(ctx, caller.TenantID, clientID, claims)
			if err != nil {
				return nil, err
			}
			if !allowed {
				s.auditIntrospectionRefused(ctx, caller.TenantID, clientID, claims.ClientID)
				return inactive, nil
			}
			// Introspection is authoritative on revocation: a token whose account,
			// membership or agent is no longer active is inactive here, even though its
			// signature still verifies.
			live, err := s.tokenSubjectLive(ctx, claims)
			if err != nil {
				return nil, err
			}
			if !live {
				return inactive, nil
			}
			out := map[string]any{
				"active":     true,
				"token_type": "Bearer",
				"sub":        claims.Subject,
				"scope":      claims.Scope,
				"iss":        s.issuer.JWTIssuer(),
				"aud":        audienceClaim(claims.Audience),
			}
			if claims.ClientID != "" {
				out["client_id"] = claims.ClientID
			}
			if res := resourcesOf(claims.Audience, s.issuer.JWTAudience()); len(res) > 0 {
				out["resource"] = audienceClaim(res)
			}
			if claims.ExpiresAt != nil {
				out["exp"] = claims.ExpiresAt.Unix()
			}
			if claims.IssuedAt != nil {
				out["iat"] = claims.IssuedAt.Unix()
			}
			if claims.TenantID != uuid.Nil {
				out["tenant_id"] = claims.TenantID
			}
			if claims.SessionID != uuid.Nil {
				out["sid"] = claims.SessionID
			}
			// Actor context so resource/MCP servers can authorize non-user
			// principals distinctly (agent vs service) and see delegation.
			if claims.ActorType != "" {
				out["actor_type"] = claims.ActorType
			}
			if claims.AgentID != "" {
				out["agent_id"] = claims.AgentID
			}
			if claims.Act != nil && claims.Act.Subject != "" {
				out["act"] = map[string]any{"sub": claims.Act.Subject}
			}
			return out, nil
		}
	}

	// Refresh token (opaque, stored hashed) — unless the hint says access_token.
	if hint != "access_token" {
		row, err := s.q.GetRefreshTokenForIntrospect(ctx, tokens.HashRefresh(token))
		if errors.Is(err, pgx.ErrNoRows) {
			return inactive, nil
		}
		if err != nil {
			return nil, err
		}
		// Active = not revoked, not yet rotated (used), and unexpired.
		if row.RevokedAt.Valid || row.UsedAt.Valid || !time.Now().Before(row.ExpiresAt) {
			return inactive, nil
		}
		// Refresh tokens record their issuing client, so bind exactly — this is
		// the same check RevokeToken already performs.
		if row.ClientID != clientID {
			return inactive, nil
		}
		return map[string]any{
			"active":     true,
			"token_type": "refresh_token",
			"client_id":  row.ClientID,
			"sub":        row.UserID,
			"tenant_id":  row.TenantID,
			"scope":      strings.Join(row.Scopes, " "),
			"iat":        row.IssuedAt.Unix(),
			"exp":        row.ExpiresAt.Unix(),
		}, nil
	}

	return inactive, nil
}
