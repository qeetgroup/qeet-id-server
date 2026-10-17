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
	// SignedInAt is set for a principal authenticated by the hosted login's
	// session cookie, which has no API session: when that sign-in happened. A
	// fresh one counts as a step-up (see mfa.Service.StepUpGate).
	SignedInAt *time.Time
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

// trustedProxyHops is the number of reverse proxies that sit in front of this
// server and APPEND to X-Forwarded-For. Set once at startup from
// TRUSTED_PROXY_HOPS (see SetTrustedProxyHops); read on every request.
//
// It is package-level because ClientIP is called from ~90 sites and threading
// configuration through all of them would buy nothing: the value is written
// once during composition, before the listener accepts a connection, and is
// read-only thereafter. atomic.Int32 keeps that write/read pair race-free.
var trustedProxyHops atomic.Int32

// SetTrustedProxyHops declares how many trusted reverse proxies front this
// server. Call it from the composition root before serving.
//
// 0 (the default) means "no trusted proxy": X-Forwarded-For is ignored
// entirely and the client IP is the transport peer. That is the only safe
// default — the header is attacker-controlled unless something we trust
// rewrote it.
func SetTrustedProxyHops(n int) {
	if n < 0 {
		n = 0
	}
	trustedProxyHops.Store(int32(n))
}

// ClientIP resolves the originating client IP for rate limiting, audit records
// and access logs.
//
// # Why this is positional rather than left-most
//
// X-Forwarded-For is a client-supplied header. Reverse proxies conventionally
// APPEND the peer they received the connection from rather than replacing the
// header, so a request arriving as
//
//	X-Forwarded-For: 1.2.3.4          (attacker-chosen)
//
// is forwarded by one proxy as
//
//	X-Forwarded-For: 1.2.3.4, <real client>
//
// Taking the LEFT-most entry therefore returns whatever the caller typed. That
// is what this function used to do, and it made the per-IP login limiter
// trivially bypassable (a fresh token bucket per forged value = unlimited
// credential stuffing) and let a caller forge the source IP recorded in the
// tenant's audit log.
//
// Counting from the RIGHT is spoof-resistant: the last N entries are the ones
// our own N trusted proxies appended, so the entry immediately left of them is
// the address the outermost trusted proxy actually saw. Anything further left
// is caller-supplied and ignored.
//
// X-Real-IP is deliberately NOT consulted. It carries a single value with no
// positional structure, so there is no way to distinguish a proxy-set value
// from a caller-set one, and the common proxies pass a caller-supplied one
// through untouched.
func ClientIP(r *http.Request) string {
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
