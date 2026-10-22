// Package httpx provides reusable HTTP middleware and response helpers.
package httpx

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

type ctxKey string

const ctxKeyPrincipal ctxKey = "qeet.principal"

// Principal is the authenticated caller of a request.
type Principal struct {
	UserID    *uuid.UUID
	TenantID  *uuid.UUID
	ActorType string
	Scopes    []string
	Subject   string
	SessionID *uuid.UUID
	// AgentID is set when the token is an AI-agent token (ActorType == "agent").
	AgentID *uuid.UUID
	// ClientID is set when the token was issued to an application through the
	// authorization server (its client_id claim); empty for the user's own
	// tokens. See RefuseApplicationTokens.
	ClientID string
	// SignedInAt is when a principal authenticated by the hosted login's session
	// cookie (no API session) proved a second factor, such as a passkey; nil
	// otherwise. A recent one counts as step-up (see mfa.Service.StepUpGate).
	SignedInAt *time.Time
}

// WithPrincipal returns a copy of ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal, p)
}

// PrincipalFromCtx returns the Principal in ctx, or nil if there is none.
func PrincipalFromCtx(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKeyPrincipal).(*Principal)
	return p
}

// RequestID returns the ID chi's RequestID middleware gave r, or "".
func RequestID(r *http.Request) string {
	return middleware.GetReqID(r.Context())
}

// trustedProxyHops is how many reverse proxies in front of this server append to
// X-Forwarded-For. It is package-level because ClientIP has many callers; it is
// set once by SetTrustedProxyHops before serving and read on every request.
var trustedProxyHops atomic.Int32

// SetTrustedProxyHops sets how many trusted reverse proxies front this server
// (negative means 0); call it before serving. The default 0 ignores
// X-Forwarded-For entirely, the only safe choice, as the header is
// caller-controlled unless a trusted proxy rewrote it.
func SetTrustedProxyHops(n int) {
	if n < 0 {
		n = 0
	}
	trustedProxyHops.Store(int32(n))
}

// ClientIP returns the client's IP for rate limiting, audit and logs: the
// address a keyed relay names (see SetRelayKeys), else the X-Forwarded-For entry
// just left of those our trusted proxies appended (anything further left is
// caller-chosen), else the transport peer. X-Real-IP is never trusted.
func ClientIP(r *http.Request) string {
	if ip := relayedClientIP(r); ip != "" {
		return ip
	}
	if hops := int(trustedProxyHops.Load()); hops > 0 {
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			parts := strings.Split(v, ",")
			// The right-most `hops` entries were appended by our proxies; the
			// client is the entry immediately to their left.
			if idx := len(parts) - hops; idx >= 0 && idx < len(parts) {
				if ip := strings.TrimSpace(parts[idx]); ip != "" {
					return normalizeIP(ip)
				}
			}
			// Chain shorter than declared — a request that did not traverse the
			// full proxy path. Fall through to the transport peer rather than
			// trusting a truncated chain.
		}
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
