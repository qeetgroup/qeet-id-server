package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// ExchangeCode swaps an authorization_code for tokens.
func (s *Service) ExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, codeVerifier, resource string) (*TokenResponse, error) {
	client, clientInfo, err := s.codeClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	hash := codes.Hash(code)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	ac, resource, refusal, err := s.redeemableCode(ctx, tx, q, clientID, hash, redirectURI, resource)
	if err == nil && refusal == nil {
		err = checkProofKey(ac, clientInfo, codeVerifier)
	}
	if err == nil && refusal == nil {
		refusal, err = s.spendCode(ctx, q, hash, ac.UserID, ac.OrganizationID)
	}
	if err != nil {
		return nil, err
	}
	// A refusal commits what it wrote: the spent code, the ended grant.
	if refusal != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, refusal
	}
	// The grant is written while the code is still locked, so a sign-out of
	// the hosted-login session the code came from either spends the code first
	// (and this redemption fails) or waits and then ends the grant.
	refresh := ""
	if issuesRefreshToken(clientInfo.Scopes, client.GrantTypes, ac.Scopes) {
		refresh, err = s.issueRefreshToken(ctx, q, clientID, ac.UserID, ac.OrganizationID, ac.Scopes, resource, ac.LoginSessionID, hash, ac.AuthTime)
		if err != nil {
			return nil, err
		}
	}
	if err := user.RecordActive(ctx, tx, ac.OrganizationID, ac.UserID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.codeTokens(ctx, clientID, ac, resource, refresh)
}

// codeClient authenticates the client redeeming a code and reads its
// settings. A client no longer registered for codes redeems none it was
// issued.
func (s *Service) codeClient(ctx context.Context, clientID, clientSecret string) (authedClient, dbgen.GetClientForAuthRow, error) {
	var info dbgen.GetClientForAuthRow
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return client, info, err
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") {
		return client, info, ErrGrantTypeNotAllowed
	}
	info, err = s.q.GetClientForAuth(ctx, clientID)
	return client, info, err
}

// redeemableCode locks clientID's code by its hash and checks it may still be
// redeemed at redirectURI for resource, returning it with the resource the
// token is for. A code presented twice ends what its first redemption issued
// and is refused, which commits; err is a refusal that keeps nothing.
func (s *Service) redeemableCode(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, clientID, hash, redirectURI, resource string) (dbgen.ConsumeAuthorizationCodeRow, string, error, error) {
	ac, err := q.ConsumeAuthorizationCode(ctx, dbgen.ConsumeAuthorizationCodeParams{CodeHash: hash, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ac, resource, nil, ErrAuthCodeInvalid
	}
	if err != nil {
		return ac, resource, nil, err
	}
	if ac.UsedAt != nil {
		// A code presented twice was seen by someone else: end what its first
		// redemption issued (RFC 6749 §4.1.2), then refuse.
		if err := s.revokeGrantFromCode(ctx, tx, clientID, hash, ac.UserID, ac.OrganizationID); err != nil {
			return ac, resource, nil, err
		}
		return ac, resource, ErrAuthCodeUsed, nil
	}
	if time.Now().After(ac.ExpiresAt) {
		return ac, resource, nil, ErrAuthCodeExpired
	}
	if ac.RedirectUri != redirectURI {
		return ac, resource, nil, ErrRedirectURIMismatch
	}
	// The token is for the resource the authorization named; a token request
	// may repeat it but not name another.
	if ac.Resource != nil && *ac.Resource != "" {
		if resource != "" && resource != *ac.Resource {
			return ac, resource, nil, oauthErr("invalid_target", "resource differs from the one the authorization was for")
		}
		resource = *ac.Resource
	}
	if err := checkResource(ctx, q, ac.OrganizationID, resource); err != nil {
		return ac, resource, nil, err
	}
	return ac, resource, nil, nil
}

// checkProofKey checks codeVerifier against the code's PKCE challenge. A code
// issued with no challenge redeems only while its confidential application's
// exemption is still in force.
func checkProofKey(ac dbgen.ConsumeAuthorizationCodeRow, clientInfo dbgen.GetClientForAuthRow, codeVerifier string) error {
	challenge, method := ac.CodeChallenge, ac.CodeChallengeMethod
	if (challenge == nil || *challenge == "") && (clientInfo.Type != "confidential" || !clientInfo.PkceExempt) {
		return ErrCodeChallengeRequired
	}
	if challenge != nil && *challenge != "" {
		if codeVerifier == "" {
			return ErrCodeVerifierRequired
		}
		if !validPKCEValue(codeVerifier, 43, 128) {
			return ErrCodeVerifierInvalid
		}
		// We support S256 only (the recommended PKCE method).
		if method == nil || *method != "S256" {
			return ErrCodeChallengeMethodUnsupported
		}
		computed := codes.Hash(codeVerifier)
		if subtle.ConstantTimeCompare([]byte(computed), []byte(*challenge)) != 1 {
			return ErrCodeVerifierInvalid
		}
	}
	return nil
}

// spendCode marks the code used. A code issued before the account was
// suspended or deleted, or before its person left the application's
// organization, is spent, not redeemed: it returns the refusal to commit.
func (s *Service) spendCode(ctx context.Context, q *dbgen.Queries, hash string, userID, organizationID uuid.UUID) (error, error) {
	active, err := accountActive(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	member, err := s.activeOrganizationPrincipal(ctx, q, userID, organizationID)
	if err != nil {
		return nil, err
	}
	if err := q.MarkAuthorizationCodeUsed(ctx, hash); err != nil {
		return nil, err
	}
	if !active {
		return errs.ErrAuthAccountSuspended, nil
	}
	if !member {
		return ErrUserOrganizationMismatch, nil
	}
	return nil, nil
}

// codeTokens mints the access token, and the ID token when the code's scopes
// include openid, of a redeemed code, with its refresh token.
func (s *Service) codeTokens(ctx context.Context, clientID string, ac dbgen.ConsumeAuthorizationCodeRow, resource, refresh string) (*TokenResponse, error) {
	userID, organizationID, scopes := ac.UserID, ac.OrganizationID, ac.Scopes
	// RFC 8707: bind the token's audience to the requested resource (if any).
	// Its sid is the hosted-login session, as the ID token's is.
	access, _, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, OrganizationID: organizationID, SessionID: postgres.ZeroIfNull(ac.LoginSessionID), Scopes: strings.Join(scopes, " "), Resource: resource, ClientID: clientID,
	})
	if err != nil {
		return nil, err
	}
	idTok := ""
	if slices.Contains(scopes, "openid") {
		t, err := s.signIDToken(ctx, idToken{
			UserID: userID, OrganizationID: organizationID, Audience: clientID, Nonce: strutil.Deref(ac.Nonce), Scopes: scopes,
			AuthTime: postgres.ZeroIfNull(ac.AuthTime), SessionID: postgres.ZeroIfNull(ac.LoginSessionID),
		})
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// revokeGrantFromCode ends the grant redeemed from the authorization code
// with this hash, after the code was presented again, and records it.
func (s *Service) revokeGrantFromCode(ctx context.Context, tx pgx.Tx, clientID, codeHash string, userID, organizationID uuid.UUID) error {
	n, err := s.q.WithTx(tx).RevokeGrantFromCode(ctx, dbgen.RevokeGrantFromCodeParams{
		ClientID: clientID, AuthorizationCodeHash: &codeHash,
	})
	if err != nil {
		return err
	}
	return audit.Record(ctx, tx, audit.Actor{UserID: &userID, Type: "system"}.Event(organizationID, "oidc.authorization_code_reused", "oidc_client", uuid.Nil,
		map[string]any{"client_id": clientID, "grants_revoked": n, "reason": "authorization_code_reuse"}))
}
