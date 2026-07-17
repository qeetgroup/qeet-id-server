package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/domains/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/security/tokens"
)

// LoginSessionCookie is the browser SSO cookie for the hosted login/consent
// flow. It proves the browser is signed in to the Qeet ID identity provider and
// is HttpOnly (never readable by JS) — distinct from API access/refresh tokens.
const LoginSessionCookie = "qe_ls"

// loginSessionTTL is the idle lifetime of a hosted SSO session.
const loginSessionTTL = 30 * time.Minute

// CreateLoginSession mints a hosted SSO session for a user and returns the raw
// cookie value. Only the hash is persisted (like refresh tokens).
func (s *Service) CreateLoginSession(ctx context.Context, userID uuid.UUID, ip, ua string) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	if err := s.q.InsertLoginSession(ctx, dbgen.InsertLoginSessionParams{
		TokenHash: hash,
		UserID:    userID,
		ExpiresAt: time.Now().Add(loginSessionTTL),
		Ip:        ip,
		UserAgent: &ua,
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// ResolveLoginSession returns the user id behind a valid, unexpired SSO session
// cookie value, or ErrUnauthorized.
func (s *Service) ResolveLoginSession(ctx context.Context, raw string) (uuid.UUID, error) {
	if raw == "" {
		return uuid.Nil, errs.ErrUnauthorized
	}
	row, err := s.q.GetLoginSession(ctx, tokens.HashRefresh(raw))
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrUnauthorized
	}
	if err != nil {
		return uuid.Nil, err
	}
	if time.Now().After(row.ExpiresAt) {
		return uuid.Nil, errs.ErrUnauthorized
	}
	return row.UserID, nil
}

// RevokeLoginSession deletes a hosted SSO session (hosted logout).
func (s *Service) RevokeLoginSession(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	return s.q.DeleteLoginSession(ctx, tokens.HashRefresh(raw))
}

// SetLoginSessionCookie writes the HttpOnly SSO cookie. secure should be true
// outside dev so it is only sent over HTTPS. SameSite=Lax so it survives the
// top-level GET redirects of the OAuth authorize flow.
func SetLoginSessionCookie(w http.ResponseWriter, raw string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginSessionCookie,
		Value:    raw,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(loginSessionTTL.Seconds()),
	})
}

// ClearLoginSessionCookie expires the SSO cookie.
func ClearLoginSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginSessionCookie,
		Value:    "",
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
