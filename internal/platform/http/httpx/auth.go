package httpx

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// AuthVerifier resolves a bearer token to a Principal.
type AuthVerifier struct {
	Tokens          *tokens.Issuer
	DevTrustHeaders bool
	// AgentStatus, when set, returns the current lifecycle status of an AI-agent
	// (by agent_id). It is consulted on every agent token so that suspending or
	// decommissioning an agent denies its already-issued (stateless) tokens
	// within one request cycle. nil skips the check.
	AgentStatus func(ctx context.Context, agentID uuid.UUID) (string, error)
	// SessionUsed, when set, is told of each request made with the access
	// token of one of the user's own sessions (not an application's token),
	// so the session's last use is known. Best effort; nil skips it.
	SessionUsed func(ctx context.Context, sessionID uuid.UUID)
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
				w.Header().Set("WWW-Authenticate", `Bearer realm="qeet"`)
				WriteError(w, r, errs.ErrUnauthorized)
				return
			}
			raw := strings.TrimSpace(auth[len("bearer "):])
			claims, err := v.Tokens.VerifyAccess(raw)
			if err != nil {
				// Wrap, not WithDetail: the cause echoes caller-chosen header
				// values (such as an unknown kid) and would reveal our
				// key-rotation state. WriteError logs it; the client gets a 401.
				w.Header().Set("WWW-Authenticate", `Bearer realm="qeet", error="invalid_token"`)
				WriteError(w, r, errs.ErrUnauthorized.Wrap(err))
				return
			}
			p := &Principal{
				ActorType: "user",
				Subject:   claims.Subject,
				Scopes:    strings.Fields(claims.Scope),
			}
			if claims.ActorType != "" {
				p.ActorType = claims.ActorType
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
			p.ClientID = claims.ClientID
			if v.SessionUsed != nil && p.SessionID != nil && p.ClientID == "" && p.ActorType == "user" {
				v.SessionUsed(r.Context(), *p.SessionID)
			}
			// AI-agent token: capture the agent id and enforce the agent's
			// current lifecycle status, so a suspended/decommissioned agent's
			// still-valid tokens are denied immediately (within one request).
			if claims.AgentID != "" {
				if aid, perr := uuid.Parse(claims.AgentID); perr == nil {
					p.AgentID = &aid
					if v.AgentStatus != nil {
						status, serr := v.AgentStatus(r.Context(), aid)
						if serr != nil || status != "active" {
							detail := "revoked"
							if serr == nil {
								detail = status
							}
							WriteError(w, r, errs.ErrUnauthorized.WithDetail("agent "+detail))
							return
						}
					}
				}
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// EnforceTenantScope rejects a request whose route has a {tenantID} path param
// other than the caller's own tenant, so a handler can't serve another tenant's
// data even if it forgets to check. Routes without the param pass through;
// their handlers scope themselves.
func EnforceTenantScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pathTenant := chi.URLParam(r, "tenantID"); pathTenant != "" {
			want, err := RequireTenant(r)
			if err != nil {
				WriteError(w, r, err)
				return
			}
			got, perr := uuid.Parse(pathTenant)
			if perr != nil {
				WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
				return
			}
			if got != want {
				WriteError(w, r, errs.ErrForbidden.WithDetail("tenant mismatch"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// PathTenant returns the caller's tenant once the {tenantID} path parameter
// names it: bad_request for a malformed parameter, forbidden for another
// tenant's. It repeats EnforceTenantScope's check inside a handler.
func PathTenant(r *http.Request) (uuid.UUID, error) {
	return PathTenantOr(r, errs.ErrBadRequest.WithDetail("invalid tenantID"), errs.ErrForbidden.WithDetail("tenant mismatch"))
}

// PathTenantOr is PathTenant answering a malformed parameter with invalid and
// another tenant's with mismatch, for a domain with its own error codes.
func PathTenantOr(r *http.Request, invalid, mismatch error) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, invalid
	}
	scope, err := RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, mismatch
	}
	return scope, nil
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
