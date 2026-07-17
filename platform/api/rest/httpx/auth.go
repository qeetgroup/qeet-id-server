package httpx

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/database/rlsctx"
	"github.com/qeetgroup/qeet-id/platform/security/tokens"
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

// EnforceTenantScope rejects any request whose matched route carries a
// {tenantID} path param that isn't the authenticated caller's own tenant.
// Mounted once on the authed route group, it closes the entire class of
// cross-tenant "trust the path tenant" bugs (QID-18) centrally, so a handler
// physically cannot serve another tenant's data even if it forgets to check.
// Routes without a {tenantID} param (e.g. /users/{id}, /roles/{roleID}) pass
// through untouched — those are scoped by their own handlers.
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
			// Propagate the validated tenant scope so the DB pool can stamp it
			// onto the connection for Row-Level Security (defense-in-depth
			// backstop to the handlers' own tenant_id predicates). Only routes
			// with a matched {tenantID} carry this; account-level/self-scoped
			// routes intentionally do not (they run with RLS bypassed).
			r = r.WithContext(rlsctx.WithTenant(r.Context(), got))
		}
		next.ServeHTTP(w, r)
	})
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
