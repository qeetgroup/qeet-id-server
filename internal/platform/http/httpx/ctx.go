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

// ClientIP resolves the originating client IP, preferring proxy headers set by
// the edge (Caddy/nginx) so audit records carry the real caller rather than the
// loadbalancer or a loopback address.
//
// X-Forwarded-For is a comma-separated chain "client, proxy1, proxy2"; the
// left-most entry is the original client, so we take that (not the whole list,
// which is not a valid INET and would fail to store). X-Real-IP is a single
// value. We fall back to the transport RemoteAddr host. IPv4-mapped IPv6
// addresses (::ffff:1.2.3.4) are unwrapped to their dotted-quad form.
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		first := v
		if i := strings.IndexByte(v, ','); i >= 0 {
			first = v[:i]
		}
		if ip := strings.TrimSpace(first); ip != "" {
			return normalizeIP(ip)
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return normalizeIP(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return normalizeIP(strings.TrimSpace(r.RemoteAddr))
	}
	return normalizeIP(host)
}

// normalizeIP unwraps IPv4-mapped IPv6 addresses and strips CR/LF for logging.
func normalizeIP(v string) string {
	if ip := net.ParseIP(v); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return SanitizeForLog(v)
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
