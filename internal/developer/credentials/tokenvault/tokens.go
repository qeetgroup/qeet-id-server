package tokenvault

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// GetAccessToken returns a live access token for (organizationID, userID,
// provider), refreshing it first if it's expired (or about to be) and a refresh
// token is on file, once its read is recorded as actor's: a read that can't be
// recorded is refused. The refresh token is never returned, only used to mint
// a new access token.
func (s *Service) GetAccessToken(ctx context.Context, organizationID, userID uuid.UUID, provider string, actor audit.Actor) (string, error) {
	token, err := s.accessToken(ctx, organizationID, userID, provider)
	if err != nil {
		return "", err
	}
	if err := audit.RecordAlone(ctx, s.pool, actor.Event(organizationID, "vault.tokens.accessed", "token_vault_grant", uuid.Nil,
		map[string]any{"provider": provider})); err != nil {
		return "", err
	}
	return token, nil
}

// accessToken is GetAccessToken's token, before its read is recorded.
func (s *Service) accessToken(ctx context.Context, organizationID, userID uuid.UUID, provider string) (string, error) {
	grant, err := s.q.GetTokenGrant(ctx, dbgen.GetTokenGrantParams{OrganizationID: organizationID, UserID: userID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrTokenVaultGrantNotFound
	}
	if err != nil {
		return "", err
	}
	if !dueForRefresh(grant.ExpiresAt) {
		return s.decrypt(organizationID, userID, provider, "token-vault-access", grant.AccessTokenCt, grant.AccessTokenNonce)
	}
	return s.refresh(ctx, organizationID, userID, provider)
}

// recordRefusal records that actor, a credential other than a person's own
// session, was refused provider's token, with metadata naming it. Losing the
// record costs the audit only, so it is logged and the refusal stands.
func (s *Service) recordRefusal(ctx context.Context, organizationID uuid.UUID, provider string, actor audit.Actor, metadata map[string]any) {
	metadata["provider"] = provider
	if err := audit.RecordAlone(ctx, s.pool, actor.Event(organizationID, "vault.tokens.access_refused", "token_vault_grant", uuid.Nil, metadata)); err != nil {
		slog.Warn("tokenvault: record a refused token read", "organization_id", organizationID, "err", err)
	}
}

// dueForRefresh reports whether a token expiring at expiresAt (none: never)
// should be refreshed before it is handed out.
func dueForRefresh(expiresAt *time.Time) bool {
	return expiresAt != nil && !time.Now().Before(expiresAt.Add(-expirySkew))
}

// refresh renews a grant due for it and returns its new access token. The
// grant's row is locked and read again first, so of two reads at once one
// refreshes and the other gets what it got: a provider that rotates refresh
// tokens never sees one presented twice.
func (s *Service) refresh(ctx context.Context, organizationID, userID uuid.UUID, provider string) (string, error) {
	clientID, clientSecret, _, tokenURL, _, err := s.providerConfig(ctx, organizationID, provider)
	if err != nil {
		return "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	grant, err := q.LockTokenGrant(ctx, dbgen.LockTokenGrantParams{OrganizationID: organizationID, UserID: userID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrTokenVaultGrantNotFound
	}
	if err != nil {
		return "", err
	}
	if !dueForRefresh(grant.ExpiresAt) {
		return s.decrypt(organizationID, userID, provider, "token-vault-access", grant.AccessTokenCt, grant.AccessTokenNonce)
	}
	if grant.RefreshTokenCt == nil {
		// Expired with no refresh token on file — the caller must reconnect.
		return "", ErrTokenExpired
	}
	refreshToken, err := s.decrypt(organizationID, userID, provider, "token-vault-refresh", grant.RefreshTokenCt, grant.RefreshTokenNonce)
	if err != nil {
		return "", err
	}
	tok, err := s.exchange(ctx, tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return "", err
	}
	// Most providers omit refresh_token on a refresh response, meaning "keep
	// using the one you have" — preserve it rather than losing it.
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	if err := s.storeGrant(ctx, q, organizationID, userID, provider, tokenURL, clientID, tok); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// ListGrants returns the providers the user has connected, without their
// tokens.
func (s *Service) ListGrants(ctx context.Context, organizationID, userID uuid.UUID) ([]GrantMeta, error) {
	rows, err := s.q.ListGrants(ctx, dbgen.ListGrantsParams{OrganizationID: organizationID, UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]GrantMeta, 0, len(rows))
	for _, row := range rows {
		out = append(out, GrantMeta{
			Provider:          row.Provider,
			ExternalAccountID: row.ExternalAccountID,
			Scope:             row.Scope,
			ExpiresAt:         row.ExpiresAt,
			CreatedAt:         row.CreatedAt,
			UpdatedAt:         row.UpdatedAt,
		})
	}
	return out, nil
}

// Disconnect deletes the user's stored tokens for a provider.
func (s *Service) Disconnect(ctx context.Context, organizationID, userID uuid.UUID, provider string) error {
	n, err := s.q.DeleteGrant(ctx, dbgen.DeleteGrantParams{OrganizationID: organizationID, UserID: userID, Provider: provider})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrTokenVaultGrantNotFound
	}
	return nil
}
