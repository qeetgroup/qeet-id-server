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
	if !redirectRegistered(info.RedirectUris, redirectURI) {
		return "", uuid.Nil, errs.ErrOIDCRedirectURIInvalid
	}
	if !contains(info.GrantTypes, "authorization_code") {
		return "", uuid.Nil, errs.ErrOIDCGrantTypeNotAllowed
	}
	for _, sc := range scopes {
		if !scopePermitted(info.Scopes, info.GrantTypes, sc) {
			return "", uuid.Nil, errs.ErrOIDCScopeNotPermitted
		}
	}
	if err := validateSignInRequest(info.Type, info.PkceExempt, nonce, challenge, challengeMethod); err != nil {
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

// scopeOfflineAccess is the OpenID scope that asks for a refresh token, to act
// while the person is away (OIDC Core §11).
const scopeOfflineAccess = "offline_access"

// scopePermitted reports whether a client registered for scopes and grantTypes
// may request scope: one it registered, or offline_access when it may renew.
func scopePermitted(scopes, grantTypes []string, scope string) bool {
	return contains(scopes, scope) || (scope == scopeOfflineAccess && contains(grantTypes, "refresh_token"))
}

// issuesRefreshToken reports whether a grant of granted to a client registered
// for scopes and grantTypes comes with a refresh token. Never without the
// refresh_token grant. A client that registered offline_access gets one only
// when that was granted (OIDC Core §11); any other gets one with every grant.
func issuesRefreshToken(scopes, grantTypes, granted []string) bool {
	if !contains(grantTypes, "refresh_token") {
		return false
	}
	return !contains(scopes, scopeOfflineAccess) || contains(granted, scopeOfflineAccess)
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

// activeClientTenantMember reports whether userID is an active member of the
// client's active tenant: its own account, or holding a role there.
func (s *Service) activeClientTenantMember(ctx context.Context, userID uuid.UUID, clientID string) (bool, error) {
	return s.q.IsActiveClientMember(ctx, dbgen.IsActiveClientMemberParams{UserID: userID, ClientID: clientID})
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
