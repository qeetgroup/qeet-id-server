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
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// mayIntrospect reports whether clientID may see an access token of its
// organization: it is the application the token was issued to (client_id claim), or
// it serves one of the registered resources the token was issued for.
func (s *Service) mayIntrospect(ctx context.Context, organizationID uuid.UUID, clientID string, claims *tokens.Claims) (bool, error) {
	if claims.ClientID != "" && claims.ClientID == clientID {
		return true, nil
	}
	res := resourcesOf(claims.Audience, s.issuer.JWTAudience())
	if len(res) == 0 {
		return false, nil
	}
	return s.q.ResourceServedBy(ctx, dbgen.ResourceServedByParams{OrganizationID: organizationID, ClientID: &clientID, Identifiers: res})
}

// auditIntrospectionRefused records an application asking about a token it
// doesn't own (owner "" for a token issued to no application).
func (s *Service) auditIntrospectionRefused(ctx context.Context, organizationID uuid.UUID, caller, owner string) {
	_ = audit.RecordAlone(ctx, s.pool, audit.Actor{Type: "client", IP: httpx.ClientIPFromContext(ctx)}.Event(
		organizationID, "oidc.introspection_refused", "oidc_client", uuid.Nil,
		map[string]any{"client_id": caller, "token_client_id": owner, "outcome": "inactive"}))
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
	caller := audit.Actor{UserID: &first.UserID, Type: "client", IP: httpx.ClientIPFromContext(ctx)}
	if err := audit.Record(ctx, tx, caller.Event(first.OrganizationID, "oidc.grant_revoked", "oidc_grant", postgres.ZeroIfNull(first.GrantID),
		map[string]any{"client_id": client.ClientID, "tokens_revoked": len(ended), "via": "revocation_endpoint"})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Introspect implements RFC 7662. After client authentication it reports
// whether the token is active and, if so, its metadata. It recognises both our
// signed access tokens (verified statelessly) and stored OIDC refresh tokens.
// token_type_hint, when given, picks which check to run first/only.
func (s *Service) Introspect(ctx context.Context, clientID, clientSecret, token, hint string) (map[string]any, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if err := s.requireConfidential(ctx, client); err != nil {
		return nil, err
	}
	if token == "" {
		return inactiveToken(), nil
	}

	// RFC 7662 §2.1: the token must have been issued to the calling client, or this
	// endpoint becomes a token oracle for other organizations. A mismatch returns
	// active: false, which reveals nothing.
	caller, err := s.q.GetClientName(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Access token (stateless JWT) — unless the hint says it's a refresh token.
	// Whatever its audience: a token issued for a resource is still ours.
	if hint != "refresh_token" {
		if claims, err := s.issuer.VerifyAccessAnyAudience(token); err == nil {
			return s.introspectAccess(ctx, caller.OrganizationID, clientID, claims)
		}
	}

	// Refresh token (opaque, stored hashed) — unless the hint says access_token.
	if hint != "access_token" {
		return s.introspectRefresh(ctx, clientID, token)
	}

	return inactiveToken(), nil
}

// inactiveToken is the answer for a token introspection doesn't vouch for.
func inactiveToken() map[string]any { return map[string]any{"active": false} }

// introspectAccess answers for a verified access token: active, with its
// metadata, only to the application it was issued to (or a service its
// resource names), in the caller's organization, while its subject is live.
func (s *Service) introspectAccess(ctx context.Context, organizationID uuid.UUID, clientID string, claims *tokens.Claims) (map[string]any, error) {
	if claims.OrganizationID != organizationID {
		return inactiveToken(), nil
	}
	// Only the application the token was issued to, or the service a
	// registered resource it names says serves it, may see it.
	allowed, err := s.mayIntrospect(ctx, organizationID, clientID, claims)
	if err != nil {
		return nil, err
	}
	if !allowed {
		s.auditIntrospectionRefused(ctx, organizationID, clientID, claims.ClientID)
		return inactiveToken(), nil
	}
	// Introspection is authoritative on revocation: a token whose account,
	// membership or agent is no longer active is inactive here, even though its
	// signature still verifies.
	live, err := s.tokenSubjectLive(ctx, claims)
	if err != nil {
		return nil, err
	}
	if !live {
		return inactiveToken(), nil
	}
	return s.accessTokenInfo(claims), nil
}

// accessTokenInfo is an active access token's RFC 7662 metadata.
func (s *Service) accessTokenInfo(claims *tokens.Claims) map[string]any {
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
	if claims.OrganizationID != uuid.Nil {
		out["organization_id"] = claims.OrganizationID
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
	return out
}

// introspectRefresh answers for a stored refresh token: active, with its
// metadata, while it is neither revoked, rotated nor expired, and only to the
// client it was issued to.
func (s *Service) introspectRefresh(ctx context.Context, clientID, token string) (map[string]any, error) {
	row, err := s.q.GetRefreshTokenForIntrospect(ctx, tokens.HashRefresh(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return inactiveToken(), nil
	}
	if err != nil {
		return nil, err
	}
	// Active = not revoked, not yet rotated (used), and unexpired.
	if row.RevokedAt != nil || row.UsedAt != nil || !time.Now().Before(row.ExpiresAt) {
		return inactiveToken(), nil
	}
	// Refresh tokens record their issuing client, so bind exactly — this is
	// the same check RevokeToken already performs.
	if row.ClientID != clientID {
		return inactiveToken(), nil
	}
	return map[string]any{
		"active":          true,
		"token_type":      "refresh_token",
		"client_id":       row.ClientID,
		"sub":             row.UserID,
		"organization_id": row.OrganizationID,
		"scope":           strings.Join(row.Scopes, " "),
		"iat":             row.IssuedAt.Unix(),
		"exp":             row.ExpiresAt.Unix(),
	}, nil
}
