package httpx

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/tokens"
)

// AuthVerifier resolves a bearer token to a Principal.
type AuthVerifier struct {
	Tokens          *tokens.Issuer
	DevTrustHeaders bool
}

// RequireAuth wraps a handler so it only sees authenticated requests.
func RequireAuth(v *AuthVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// An earlier middleware (e.g. the API-key middleware) may have
			// already authenticated the request. Honor that principal rather
			// than insisting on a bearer token / dev header.
			if PrincipalFromCtx(r.Context()) != nil {
				next.ServeHTTP(w, r)
				return
			}
			if v.DevTrustHeaders {
				if devUser := r.Header.Get("X-Dev-User"); devUser != "" {
					p := &Principal{ActorType: "user", Subject: devUser}
					if uid, err := uuid.Parse(devUser); err == nil {
						p.UserID = &uid
					}
					if devTenant := r.Header.Get("X-Dev-Tenant"); devTenant != "" {
						if tid, err := uuid.Parse(devTenant); err == nil {
							p.TenantID = &tid
						}
					}
					next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
					return
				}
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				WriteError(w, r, errs.ErrUnauthorized)
				return
			}
			raw := strings.TrimSpace(auth[len("bearer "):])
			claims, err := v.Tokens.VerifyAccess(raw)
			if err != nil {
				WriteError(w, r, errs.ErrUnauthorized.WithDetail(err.Error()))
				return
			}
			p := &Principal{
				ActorType: "user",
				Subject:   claims.Subject,
				Scopes:    strings.Fields(claims.Scope),
			}
			if claims.UserID != uuid.Nil {
				uid := claims.UserID
				p.UserID = &uid
			}
			if claims.TenantID != uuid.Nil {
				tid := claims.TenantID
				p.TenantID = &tid
			}
			if claims.SessionID != uuid.Nil {
				sid := claims.SessionID
				p.SessionID = &sid
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// RequireTenant returns the principal's tenant id — the only trustworthy
// source of tenant scope. Handlers must never take tenant id from URL/body.
func RequireTenant(r *http.Request) (uuid.UUID, error) {
	p := PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		return uuid.Nil, errs.ErrUnauthorized.WithDetail("tenant scope required")
	}
	return *p.TenantID, nil
}

// RequireUser returns the principal's user id, or an error if absent.
func RequireUser(r *http.Request) (uuid.UUID, error) {
	p := PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		return uuid.Nil, errs.ErrUnauthorized
	}
	return *p.UserID, nil
}

// RequireScope blocks the request unless the principal has at least one
// of the provided scopes.
func RequireScope(scopes ...string) func(http.Handler) http.Handler {
	want := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		want[s] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := PrincipalFromCtx(r.Context())
			if p == nil {
				WriteError(w, r, errs.ErrUnauthorized)
				return
			}
			for _, s := range p.Scopes {
				if _, ok := want[s]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}
			WriteError(w, r, errs.ErrForbidden)
		})
	}
}
