package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// consentRequestTTL is how long an authorization request waits on the hosted
// consent screen before it lapses and the person starts again.
const consentRequestTTL = 10 * time.Minute

// ConsentRequest is an authorization request waiting on the hosted consent
// screen. The server stored it after checking it, so a decision acts on these
// values, never on ones the browser sends.
type ConsentRequest struct {
	ID                  uuid.UUID
	UserID              uuid.UUID
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Resource is the RFC 8707 resource the token is for ("" for none).
	Resource string
}

// StartConsentRequest stores an authorization request for the hosted consent
// screen and returns its id. The redirect_uri must already be registered for
// the client: an unregistered one is ErrOIDCRedirectURINotRegistered, and no
// request is stored.
func (s *Service) StartConsentRequest(ctx context.Context, loginSessionID, userID uuid.UUID, in ConsentRequest) (uuid.UUID, error) {
	if !s.RegisteredRedirect(ctx, in.ClientID, in.RedirectURI) {
		return uuid.Nil, errs.ErrOIDCRedirectURINotRegistered
	}
	// A request the authorization would refuse (no proof key, no nonce) is
	// refused now, not after the person has been asked to consent to it.
	info, err := s.q.GetClientRedirectInfo(ctx, in.ClientID)
	if err != nil {
		return uuid.Nil, err
	}
	if err := validateSignInRequest(info.Type, info.PkceExempt, in.Scopes, in.Nonce, in.CodeChallenge, in.CodeChallengeMethod); err != nil {
		return uuid.Nil, err
	}
	if err := s.checkResource(ctx, info.TenantID, in.Resource); err != nil {
		return uuid.Nil, err
	}
	scopes := in.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return s.q.InsertConsentRequest(ctx, dbgen.InsertConsentRequestParams{
		LoginSessionID:      loginSessionID,
		UserID:              userID,
		ClientID:            in.ClientID,
		RedirectUri:         in.RedirectURI,
		Scopes:              scopes,
		State:               in.State,
		Nonce:               in.Nonce,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(consentRequestTTL),
		Resource:            in.Resource,
	})
}

// GetConsentRequest returns an undecided request for the hosted-login session
// that started it, or ErrOIDCConsentRequestInvalid.
func (s *Service) GetConsentRequest(ctx context.Context, id, loginSessionID uuid.UUID) (*ConsentRequest, error) {
	row, err := s.q.GetConsentRequest(ctx, dbgen.GetConsentRequestParams{ID: id, LoginSessionID: loginSessionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrOIDCConsentRequestInvalid
	}
	if err != nil {
		return nil, err
	}
	return &ConsentRequest{
		ID: row.ID, UserID: row.UserID, ClientID: row.ClientID, RedirectURI: row.RedirectUri,
		Scopes: row.Scopes, State: row.State, Nonce: row.Nonce,
		CodeChallenge: row.CodeChallenge, CodeChallengeMethod: row.CodeChallengeMethod,
		Resource: row.Resource,
	}, nil
}

// TakeConsentRequest claims an undecided request for the hosted-login session
// that started it, so it can be decided exactly once. Anything else (no such
// request, another session's, decided or expired) is ErrOIDCConsentRequestInvalid.
func (s *Service) TakeConsentRequest(ctx context.Context, id, loginSessionID uuid.UUID) (*ConsentRequest, error) {
	row, err := s.q.TakeConsentRequest(ctx, dbgen.TakeConsentRequestParams{ID: id, LoginSessionID: loginSessionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrOIDCConsentRequestInvalid
	}
	if err != nil {
		return nil, err
	}
	return &ConsentRequest{
		ID: row.ID, UserID: row.UserID, ClientID: row.ClientID, RedirectURI: row.RedirectUri,
		Scopes: row.Scopes, State: row.State, Nonce: row.Nonce,
		CodeChallenge: row.CodeChallenge, CodeChallengeMethod: row.CodeChallengeMethod,
		Resource: row.Resource,
	}, nil
}
