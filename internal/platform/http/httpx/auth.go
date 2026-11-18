package httpx

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// AuthVerifier resolves a bearer token to a Principal. NewAuthVerifier checks
// that every field but DevTrustHeaders is set.
type AuthVerifier struct {
	Tokens          *tokens.Issuer
	DevTrustHeaders bool
	// AgentStatus returns the current lifecycle status of an AI-agent (by
	// agent_id). It is consulted on every agent token so that suspending or
	// decommissioning an agent denies its already-issued (stateless) tokens
	// within one request cycle.
	AgentStatus func(ctx context.Context, agentID uuid.UUID) (string, error)
	// SessionUsed is told of each request made with the access token of one of
	// the user's own sessions (not an application's token), so the session's
	// last use is known. Best effort.
	SessionUsed func(ctx context.Context, sessionID uuid.UUID)
	// SessionLive reports whether the session of a user's own access token has
	// not ended, so a signed-out, revoked or timed-out session's tokens are
	// refused at once rather than when they expire.
	SessionLive func(ctx context.Context, sessionID, userID uuid.UUID) (bool, error)
	// PrincipalLive reports whether a service principal exists and isn't
	// disabled, so disabling or deleting one refuses its tokens at once.
	PrincipalLive func(ctx context.Context, principalID uuid.UUID) (bool, error)
	// APIKeyLive reports whether an organization's API key would still
	// authenticate a request, for Live.
	APIKeyLive func(ctx context.Context, organizationID, keyID uuid.UUID) (bool, error)
}

// NewAuthVerifier returns v once it has the issuer and every liveness check,
// naming the first one missing.
func NewAuthVerifier(v AuthVerifier) (*AuthVerifier, error) {
	for name, missing := range map[string]bool{
		"token issuer": v.Tokens == nil, "agent status": v.AgentStatus == nil, "session use": v.SessionUsed == nil,
		"session liveness": v.SessionLive == nil, "service principal liveness": v.PrincipalLive == nil,
		"API key liveness": v.APIKeyLive == nil,
	} {
		if missing {
			return nil, fmt.Errorf("httpx: the request verifier needs its %s check", name)
		}
	}
	return &v, nil
}

// Live reports whether p, admitted earlier, would still be admitted, for a
// long-lived request such as an event stream: its token unexpired, its API key
// still live, and as RequireAuth checks each request, its service principal
// enabled, its agent active and its own session not ended.
func (v *AuthVerifier) Live(ctx context.Context, p *Principal) (bool, error) {
	if p == nil || (p.ExpiresAt != nil && !time.Now().Before(*p.ExpiresAt)) {
		return false, nil
	}
	switch {
	case p.ActorType == "api_key":
		id, ok := subjectID(p)
		if !ok || p.OrganizationID == nil {
			return false, nil
		}
		if live, err := v.APIKeyLive(ctx, *p.OrganizationID, id); err != nil || !live {
			return false, err
		}
	case p.ActorType == "service":
		id, ok := subjectID(p)
		if !ok {
			return false, nil
		}
		if live, err := v.PrincipalLive(ctx, id); err != nil || !live {
			return false, err
		}
	case p.AgentID != nil:
		if status, err := v.AgentStatus(ctx, *p.AgentID); err != nil || status != "active" {
			return false, err
		}
	case p.SessionID != nil && p.UserID != nil && p.ClientID == "":
		if live, err := v.SessionLive(ctx, *p.SessionID, *p.UserID); err != nil || !live {
			return false, err
		}
	}
	return true, nil
}

// subjectID is the id a machine credential's principal names as its subject;
// ok is false for one that isn't an id, which no credential of it can be.
func subjectID(p *Principal) (id uuid.UUID, ok bool) {
	id, err := uuid.Parse(p.Subject)
	return id, err == nil
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
				if p := devPrincipal(r); p != nil {
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
			p := principalOf(claims)
			if !v.sessionLive(w, r, p) || !v.servicePrincipalLive(w, r, p, claims) || !v.agentActive(w, r, p, claims) {
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// devPrincipal is the user the trusted development header X-Dev-User names, in
// the organization of X-Dev-Organization when it is one's id, or nil without
// the header.
func devPrincipal(r *http.Request) *Principal {
	devUser := r.Header.Get("X-Dev-User")
	if devUser == "" {
		return nil
	}
	p := &Principal{ActorType: "user", Subject: devUser}
	if uid, err := uuid.Parse(devUser); err == nil {
		p.UserID = &uid
	}
	if devOrganization := r.Header.Get("X-Dev-Organization"); devOrganization != "" {
		if tid, err := uuid.Parse(devOrganization); err == nil {
			p.OrganizationID = &tid
		}
	}
	return p
}

// principalOf is the principal a verified access token's claims name: a user
// unless the token says another actor type.
func principalOf(claims *tokens.Claims) *Principal {
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
	if claims.OrganizationID != uuid.Nil {
		tid := claims.OrganizationID
		p.OrganizationID = &tid
	}
	if claims.SessionID != uuid.Nil {
		sid := claims.SessionID
		p.SessionID = &sid
	}
	p.ClientID = claims.ClientID
	if claims.ExpiresAt != nil {
		exp := claims.ExpiresAt.Time
		p.ExpiresAt = &exp
	}
	return p
}

// sessionLive refuses the token of a user's own session that has ended, and
// reports a live one used. Other tokens pass. A refused request is answered
// here, and false returned.
func (v *AuthVerifier) sessionLive(w http.ResponseWriter, r *http.Request, p *Principal) bool {
	if p.SessionID == nil || p.UserID == nil || p.ClientID != "" || p.ActorType != "user" {
		return true
	}
	live, err := v.SessionLive(r.Context(), *p.SessionID, *p.UserID)
	if err != nil {
		WriteError(w, r, errs.ErrInternalServer.Wrap(err))
		return false
	}
	if !live {
		w.Header().Set("WWW-Authenticate", `Bearer realm="qeet", error="invalid_token"`)
		WriteError(w, r, errs.ErrAuthSessionRevoked)
		return false
	}
	v.SessionUsed(r.Context(), *p.SessionID)
	return true
}

// servicePrincipalLive refuses a service principal's token once the principal
// is disabled or gone. Other tokens pass. A refused request is answered here,
// and false returned.
func (v *AuthVerifier) servicePrincipalLive(w http.ResponseWriter, r *http.Request, p *Principal, claims *tokens.Claims) bool {
	if p.ActorType != "service" {
		return true
	}
	id, perr := uuid.Parse(claims.Subject)
	live := false
	if perr == nil {
		var err error
		if live, err = v.PrincipalLive(r.Context(), id); err != nil {
			WriteError(w, r, errs.ErrInternalServer.Wrap(err))
			return false
		}
	}
	if !live {
		w.Header().Set("WWW-Authenticate", `Bearer realm="qeet", error="invalid_token"`)
		WriteError(w, r, errs.ErrUnauthorized.WithDetail("service principal disabled"))
		return false
	}
	return true
}

// agentActive names an AI agent's token's agent on p and refuses the token
// unless the agent is active now, so a suspended or decommissioned agent's
// still-valid tokens are denied within one request. Other tokens pass. A
// refused request is answered here, and false returned.
func (v *AuthVerifier) agentActive(w http.ResponseWriter, r *http.Request, p *Principal, claims *tokens.Claims) bool {
	if claims.AgentID == "" {
		return true
	}
	if aid, perr := uuid.Parse(claims.AgentID); perr == nil {
		p.AgentID = &aid
		status, serr := v.AgentStatus(r.Context(), aid)
		if serr != nil || status != "active" {
			detail := "revoked"
			if serr == nil {
				detail = status
			}
			WriteError(w, r, errs.ErrUnauthorized.WithDetail("agent "+detail))
			return false
		}
	}
	return true
}

// EnforceOrganizationScope rejects a request whose route has a {organizationID} path param
// other than the caller's own organization, so a handler can't serve another organization's
// data even if it forgets to check. Routes without the param pass through;
// their handlers scope themselves.
func EnforceOrganizationScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pathOrganization := chi.URLParam(r, "organizationID"); pathOrganization != "" {
			want, err := RequireOrganization(r)
			if err != nil {
				WriteError(w, r, err)
				return
			}
			got, perr := uuid.Parse(pathOrganization)
			if perr != nil {
				WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid organizationID"))
				return
			}
			if got != want {
				WriteError(w, r, errs.ErrForbidden.WithDetail("organization mismatch"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ScopeDatabase scopes the request's database work to the caller's
// organization, so row-level security shows it only that organization's rows
// of the protected tables. A caller with no organization is left unscoped.
func ScopeDatabase(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := PrincipalFromCtx(r.Context()); p != nil && p.OrganizationID != nil && *p.OrganizationID != uuid.Nil {
			r = r.WithContext(postgres.WithOrganization(r.Context(), *p.OrganizationID))
		}
		next.ServeHTTP(w, r)
	})
}

// RequireOrganization returns the principal's organization id — the only trustworthy
// source of organization scope. Handlers must never take organization id from URL/body.
func RequireOrganization(r *http.Request) (uuid.UUID, error) {
	p := PrincipalFromCtx(r.Context())
	if p == nil || p.OrganizationID == nil {
		return uuid.Nil, errs.ErrUnauthorized.WithDetail("organization scope required")
	}
	return *p.OrganizationID, nil
}

// RequireUser returns the principal's user id, or an error if absent.
func RequireUser(r *http.Request) (uuid.UUID, error) {
	p := PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		return uuid.Nil, errs.ErrUnauthorized
	}
	return *p.UserID, nil
}
