package oidc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// issueRefreshToken stores a refresh token for the client and user and returns
// it. resource is the RFC 8707 resource bound to the access token ("" for none),
// loginSessionID the hosted-login session and authTime when the person signed
// in there (NULL for none), and codeHash the redeemed code ("" for none). q
// lets it run in the caller's transaction.
func (s *Service) issueRefreshToken(ctx context.Context, q *dbgen.Queries, clientID string, userID, organizationID uuid.UUID, scopes []string, resource string, loginSessionID *uuid.UUID, codeHash string, authTime *time.Time) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	var res *string
	if resource != "" {
		res = &resource
	}
	exp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	if err := q.InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		ID:        uuid.New(),
		TokenHash: hash, ClientID: clientID, UserID: userID, OrganizationID: organizationID,
		Scopes: scopes, ExpiresAt: exp, Resource: res, LoginSessionID: loginSessionID,
		DefaultMaxAgeSeconds: s.grantMaxAge.Seconds(), AuthorizationCodeHash: strutil.NilIfEmpty(codeHash),
		AuthTime: authTime,
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// RefreshToken handles the refresh_token grant: it rotates the token and
// reissues tokens for the original grant. Replaying a used token revokes every
// live token for the client and user. A resource (RFC 8707) other than the one
// the grant is bound to is invalid_target; none carries the bound one forward.
func (s *Service) RefreshToken(ctx context.Context, clientID, clientSecret, rawRefresh, resource string) (*TokenResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	// A client no longer registered for refresh renews nothing.
	if !slices.Contains(client.GrantTypes, "refresh_token") {
		return nil, ErrGrantTypeNotAllowed
	}
	if rawRefresh == "" {
		return nil, ErrRefreshTokenRequired
	}
	hash := tokens.HashRefresh(rawRefresh)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	rt, refusal, err := s.renewableToken(ctx, tx, q, clientID, hash)
	if err != nil {
		return nil, err
	}
	// A refusal commits the chain it ended.
	if refusal != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, refusal
	}
	// RFC 8707 §2.2: a refresh may name only the resource the grant is bound
	// to; naming none carries the bound one forward. Either way it must still be
	// registered, so a removed resource gets no new tokens.
	bound := strutil.Deref(rt.Resource)
	if resource != "" && resource != bound {
		return nil, oauthErr("invalid_target", "resource differs from the one the grant was for")
	}
	resource = bound
	if err := checkResource(ctx, q, rt.OrganizationID, resource); err != nil {
		return nil, err
	}
	// Only the granted scopes the application still registers carry forward
	// (RFC 6749 §6 lets a refresh narrow); with none left it renews nothing.
	scopes := stillPermitted(client, rt.Scopes)
	if !slices.ContainsFunc(scopes, func(sc string) bool { return sc != scopeOfflineAccess }) {
		return nil, oauthErr("invalid_scope", "the application no longer registers any scope of this grant")
	}
	newRaw, err := s.rotateRefreshToken(ctx, q, clientID, rt, scopes, resource)
	if err != nil {
		return nil, err
	}
	if err := user.RecordActive(ctx, tx, rt.OrganizationID, rt.UserID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.refreshedTokens(ctx, clientID, rt, scopes, resource, newRaw)
}

// renewableToken locks the refresh token with this hash and checks clientID
// may renew it. A suspended account's chain ends, and so does the chain of a
// token presented twice, recorded as a theft: those return the refusal to
// commit; err is a refusal that keeps nothing.
func (s *Service) renewableToken(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, clientID, hash string) (dbgen.LockRefreshTokenRow, error, error) {
	rt, err := q.LockRefreshToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return rt, nil, ErrRefreshTokenInvalid
	}
	if err != nil {
		return rt, nil, err
	}
	// A refresh token may only be redeemed by the client it was issued to.
	if rt.ClientID != clientID {
		return rt, nil, ErrRefreshTokenClientMismatch
	}
	if rt.RevokedAt != nil {
		return rt, nil, ErrRefreshTokenRevoked
	}
	// A suspended or deleted account renews nothing, and the application's
	// grants for it end, so reactivating the account doesn't revive them.
	active, err := accountActive(ctx, q, rt.UserID)
	if err != nil {
		return rt, nil, err
	}
	if !active {
		if err := q.RevokeRefreshTokenChain(ctx, dbgen.RevokeRefreshTokenChainParams{ClientID: clientID, UserID: rt.UserID}); err != nil {
			return rt, nil, err
		}
		return rt, errs.ErrAuthAccountSuspended, nil
	}
	// Nor does it renew once the person has left the application's
	// organization or the organization has been suspended.
	if live, err := s.activeOrganizationPrincipal(ctx, q, rt.UserID, rt.OrganizationID); err != nil {
		return rt, nil, err
	} else if !live {
		return rt, nil, ErrUserOrganizationMismatch
	}
	if rt.UsedAt != nil {
		// Reuse — assume theft: revoke every live token for this (client, user) and audit it.
		if err := s.handleRefreshReuse(ctx, tx, clientID, rt.UserID, rt.OrganizationID, rt.ID); err != nil {
			return rt, nil, err
		}
		return rt, ErrRefreshTokenReuse, nil
	}
	if time.Now().After(rt.ExpiresAt) {
		return rt, nil, ErrRefreshTokenExpired
	}
	return rt, nil, nil
}

// rotateRefreshToken stores the refresh token that replaces rt, for scopes
// and resource, spends rt, and returns the new token.
func (s *Service) rotateRefreshToken(ctx context.Context, q *dbgen.Queries, clientID string, rt dbgen.LockRefreshTokenRow, scopes []string, resource string) (string, error) {
	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	var newRes *string
	if resource != "" {
		newRes = &resource
	}
	newExp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	newID, err := q.InsertRotatedRefreshToken(ctx, dbgen.InsertRotatedRefreshTokenParams{
		TokenHash: newHash, ClientID: clientID, UserID: rt.UserID, OrganizationID: rt.OrganizationID,
		Scopes: scopes, ExpiresAt: newExp, Resource: newRes, LoginSessionID: rt.LoginSessionID,
		GrantExpiresAt: rt.GrantExpiresAt, AuthorizationCodeHash: rt.AuthorizationCodeHash,
		GrantID: rt.GrantID, AuthTime: rt.AuthTime,
	})
	if err != nil {
		return "", err
	}
	if err := q.MarkRefreshTokenUsed(ctx, dbgen.MarkRefreshTokenUsedParams{
		NewID: &newID,
		ID:    rt.ID,
	}); err != nil {
		return "", err
	}
	return newRaw, nil
}

// refreshedTokens mints the access token, and the ID token when scopes
// include openid, of a renewed grant, with its new refresh token.
func (s *Service) refreshedTokens(ctx context.Context, clientID string, rt dbgen.LockRefreshTokenRow, scopes []string, resource, newRaw string) (*TokenResponse, error) {
	userID := rt.UserID
	organizationID := rt.OrganizationID

	access, _, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, OrganizationID: organizationID, SessionID: postgres.ZeroIfNull(rt.LoginSessionID), Scopes: strings.Join(scopes, " "), Resource: resource, ClientID: clientID,
	})
	if err != nil {
		return nil, err
	}
	idTok := ""
	if slices.Contains(scopes, "openid") {
		// The original sign-in's time and session (OIDC Core 12.2), not now's.
		t, err := s.signIDToken(ctx, idToken{
			UserID: userID, OrganizationID: organizationID, Audience: clientID, Scopes: scopes,
			AuthTime: postgres.ZeroIfNull(rt.AuthTime), SessionID: postgres.ZeroIfNull(rt.LoginSessionID),
		})
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: newRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// stillPermitted returns the scopes of granted that client may still request.
func stillPermitted(client authedClient, granted []string) []string {
	return slices.DeleteFunc(slices.Clone(granted), func(sc string) bool {
		return !scopePermitted(client.Scopes, client.GrantTypes, sc)
	})
}

func (s *Service) handleRefreshReuse(ctx context.Context, tx pgx.Tx, clientID string, userID, organizationID, tokenID uuid.UUID) error {
	q := s.q.WithTx(tx)
	if err := q.RevokeRefreshTokenChain(ctx, dbgen.RevokeRefreshTokenChainParams{
		ClientID: clientID, UserID: userID,
	}); err != nil {
		return err
	}
	return audit.Record(ctx, tx, audit.Actor{UserID: &userID, Type: "system"}.Event(organizationID, "oidc.refresh_reuse_detected", "oidc_refresh_token", tokenID,
		map[string]any{"client_id": clientID, "refresh_token_id": tokenID, "reason": "refresh_token_reuse"}))
}
