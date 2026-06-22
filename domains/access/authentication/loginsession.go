package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/tokens"
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
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.login_sessions (token_hash, user_id, expires_at, ip, user_agent)
		VALUES ($1, $2, $3, NULLIF($4,'')::inet, $5)
	`, hash, userID, time.Now().Add(loginSessionTTL), ip, ua); err != nil {
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
	var userID uuid.UUID
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT user_id, expires_at FROM auth.login_sessions WHERE token_hash = $1
	`, tokens.HashRefresh(raw)).Scan(&userID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrUnauthorized
	}
	if err != nil {
		return uuid.Nil, err
	}
	if time.Now().After(expiresAt) {
		return uuid.Nil, errs.ErrUnauthorized
	}
	return userID, nil
}

// RevokeLoginSession deletes a hosted SSO session (hosted logout).
func (s *Service) RevokeLoginSession(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM auth.login_sessions WHERE token_hash = $1`, tokens.HashRefresh(raw))
	return err
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
