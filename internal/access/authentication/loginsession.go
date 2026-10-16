package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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

// ResolveLoginSessionUser returns the user behind a live SSO session cookie
// value and their own organization (uuid.Nil when they have none), or
// ErrUnauthorized when the session is unknown, expired or ended, or the user or
// their organization is no longer active.
func (s *Service) ResolveLoginSessionUser(ctx context.Context, raw string) (userID, tenantID uuid.UUID, err error) {
	if raw == "" {
		return uuid.Nil, uuid.Nil, errs.ErrUnauthorized
	}
	row, err := s.q.GetLoginSessionUser(ctx, tokens.HashRefresh(raw))
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, errs.ErrUnauthorized
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if row.TenantID.Valid {
		tenantID = uuid.UUID(row.TenantID.Bytes)
	}
	return row.UserID, tenantID, nil
}

// LoginSessionAuth lets the hosted login's own pages call a short list of
// signed-in routes with the browser's SSO session (the qe_ls cookie) instead of
// a bearer token, which the hosted login never holds. Mount it on the
// authenticated route group, ahead of httpx.RequireAuth.
//
// routes are "METHOD /path" entries in chi pattern syntax ("{id}" matches one
// path segment). The cookie is read only for a listed route, and only when the
// request carries no Authorization header and nothing earlier authenticated it;
// every other request passes through untouched for RequireAuth to decide. So
// the session reaches no other route, and a request presenting a token is
// judged on that token alone.
//
// Cross-site requests: the router's CSRF middleware runs first and skips only
// requests carrying "Authorization: Bearer", so a cookie-authenticated mutation
// here has already passed its Origin and qe_csrf double-submit checks.
//
// The principal is the session's user in their own organization, both read
// from the database, never from the request. An unknown, expired or ended
// session, or a user or organization that is no longer active, is refused
// with 401.
func (s *Service) LoginSessionAuth(routes []string) func(http.Handler) http.Handler {
	listed := chi.NewRouter()
	for _, route := range routes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("auth: hosted-login session route without a method: " + route)
		}
		listed.MethodFunc(method, pattern, func(http.ResponseWriter, *http.Request) {})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if httpx.PrincipalFromCtx(r.Context()) != nil || r.Header.Get("Authorization") != "" ||
				!listed.Match(chi.NewRouteContext(), r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			c, err := r.Cookie(LoginSessionCookie)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			userID, tenantID, err := s.ResolveLoginSessionUser(r.Context(), c.Value)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			p := &httpx.Principal{ActorType: "user", Subject: userID.String(), UserID: &userID}
			if tenantID != uuid.Nil {
				p.TenantID = &tenantID
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
		})
	}
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
