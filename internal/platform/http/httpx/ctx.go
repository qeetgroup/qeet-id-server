// Package httpx provides reusable HTTP middleware and response helpers.
package httpx

import (
	"context"
	"net"
	"net/http"
	"strings"

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
		return SanitizeForLog(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return SanitizeForLog(r.RemoteAddr)
	}
	return SanitizeForLog(host)
}

// SanitizeForLog strips CR/LF from a request-derived value before it is written
// into a log record, preventing log forging — an attacker injecting newlines to
// fabricate additional (fake) log entries. Use it for any user-controlled string
// that ends up in an slog field (client IP, request path, submitted email, …).
func SanitizeForLog(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return v
}
