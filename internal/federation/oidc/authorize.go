package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Authorize validates an authorization request for an authenticated user and
// returns a one-time authorization code and the client's tenant ID. The code is
// tied to no hosted-login session, so organisations with address rules refuse
// it; the browser flow uses AuthorizeInLoginSession.
func (s *Service) Authorize(ctx context.Context, userID uuid.UUID, clientID, redirectURI string, scopes []string, nonce, challenge, challengeMethod string) (string, uuid.UUID, error) {
	return s.AuthorizeInLoginSession(ctx, AuthorizeInput{
		UserID: userID, ClientID: clientID, RedirectURI: redirectURI, Scopes: scopes,
		Nonce: nonce, CodeChallenge: challenge, CodeChallengeMethod: challengeMethod,
	})
}

// AuthorizeInput is one authorization request to mint a code for.
type AuthorizeInput struct {
	// LoginSessionID is the hosted-login session the code is minted in
	// (uuid.Nil for none); signing out of it ends the code and its grant.
	LoginSessionID, UserID             uuid.UUID
	ClientID, RedirectURI              string
	Scopes                             []string
	Nonce                              string
	CodeChallenge, CodeChallengeMethod string
	// IP is the browser's address (httpx.ClientIP), which the organisation's
	// address rules must allow.
	IP string
	// Resource ("" for none) is the RFC 8707 resource the token is for, which
	// the organisation must have registered; the code carries it.
	Resource string
	// AuthTime is when the person signed in (zero: unknown); the ID token
	// reports it as auth_time.
	AuthTime time.Time
}

// AuthorizeInLoginSession mints a code for a request in a hosted-login session.
func (s *Service) AuthorizeInLoginSession(ctx context.Context, in AuthorizeInput) (string, uuid.UUID, error) {
	clientID, redirectURI, scopes := in.ClientID, in.RedirectURI, in.Scopes
	userID, loginSessionID := in.UserID, in.LoginSessionID
	nonce, challenge, challengeMethod, ip, resource := in.Nonce, in.CodeChallenge, in.CodeChallengeMethod, in.IP, in.Resource
	info, err := s.q.GetClientRedirectInfo(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrOIDCClientUnknown
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	member, err := s.activeClientTenantMember(ctx, userID, clientID)
	if err != nil {
		return "", uuid.Nil, err
	}
	if !member {
		return "", uuid.Nil, errs.ErrOIDCUserTenantMismatch
	}
	if !contains(info.RedirectUris, redirectURI) {
		return "", uuid.Nil, errs.ErrOIDCRedirectURIInvalid
	}
	if !contains(info.GrantTypes, "authorization_code") {
		return "", uuid.Nil, errs.ErrOIDCGrantTypeNotAllowed
	}
	for _, sc := range scopes {
		if !contains(info.Scopes, sc) {
			return "", uuid.Nil, errs.ErrOIDCScopeNotPermitted
		}
	}
	if err := validateSignInRequest(info.Type, info.PkceExempt, scopes, nonce, challenge, challengeMethod); err != nil {
		return "", uuid.Nil, err
	}
	if err := checkResource(ctx, s.q, info.TenantID, resource); err != nil {
		return "", uuid.Nil, err
	}
	// This is where the person signs in to the application, from the browser.
	if err := s.checkAddress(ctx, info.TenantID, userID, ip, "oidc_authorize"); err != nil {
		return "", uuid.Nil, err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", uuid.Nil, err
	}
	err = s.q.InsertAuthorizationCode(ctx, dbgen.InsertAuthorizationCodeParams{
		CodeHash:            hash,
		ClientID:            clientID,
		UserID:              userID,
		TenantID:            info.TenantID,
		RedirectUri:         redirectURI,
		Scopes:              scopes,
		Nonce:               nonce,
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		LoginSessionID:      optionalUUID(loginSessionID),
		Resource:            resource,
		AuthTime:            optionalTime(in.AuthTime),
	})
	if err != nil {
		return "", uuid.Nil, err
	}
	return raw, info.TenantID, nil
}

func validPKCEValue(value string, minLength, maxLength int) bool {
	if len(value) < minLength || len(value) > maxLength {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '.' || char == '_' || char == '~' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) activeClientTenantMember(ctx context.Context, userID uuid.UUID, clientID string) (bool, error) {
	var member bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM auth.oidc_clients c
			JOIN tenant.tenants t ON t.id = c.tenant_id
			JOIN rbac.user_roles ur ON ur.tenant_id = c.tenant_id AND ur.user_id = $1
			JOIN "user".users u ON u.id = ur.user_id
			WHERE c.client_id = $2
			  AND t.status = 'active' AND t.deleted_at IS NULL
			  AND u.status = 'active' AND u.deleted_at IS NULL
		)
	`, userID, clientID).Scan(&member)
	return member, err
}

// HasConsent reports whether the user has already granted the client every
// requested scope (so the consent screen can be skipped).
func (s *Service) HasConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) (bool, error) {
	member, err := s.activeClientTenantMember(ctx, userID, clientID)
	if err != nil {
		return false, err
	}
	if !member {
		return false, errs.ErrOIDCUserTenantMismatch
	}
	granted, err := s.q.GetConsent(ctx, dbgen.GetConsentParams{UserID: userID, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, sc := range scopes {
		if !contains(granted, sc) {
			return false, nil
		}
	}
	return true, nil
}

// GrantConsent records the user's approval of a client for the given scopes,
// replacing any prior grant for that (user, client) pair.
func (s *Service) GrantConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	member, err := s.activeClientTenantMember(ctx, userID, clientID)
	if err != nil {
		return err
	}
	if !member {
		return errs.ErrOIDCUserTenantMismatch
	}
	return s.q.UpsertConsent(ctx, dbgen.UpsertConsentParams{UserID: userID, ClientID: clientID, Scopes: scopes})
}
