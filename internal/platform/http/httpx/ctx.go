// Package httpx provides reusable HTTP middleware and response helpers.
package httpx

import (
	"context"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

type ctxKey string

const ctxKeyPrincipal ctxKey = "qeet.principal"

type Principal struct {
	UserID    *uuid.UUID
	TenantID  *uuid.UUID
	ActorType string
	Scopes    []string
	Subject   string
	SessionID *uuid.UUID
	// AgentID is set when the token is an AI-agent token (ActorType == "agent").
	AgentID *uuid.UUID
}

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal, p)
}

func PrincipalFromCtx(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKeyPrincipal).(*Principal)
	return p
}

func RequestID(r *http.Request) string {
	return middleware.GetReqID(r.Context())
}

func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
