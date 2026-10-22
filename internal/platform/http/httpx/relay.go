package httpx

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

// RelayKeyHeader and RelayClientIPHeader let a trusted first-party relay (the
// console's or hosted login's server) name the address of the person it calls
// for; otherwise everyone behind it shares its address for rate limits,
// lockout, risk and audit. Without a key from RELAY_KEYS the claim is ignored.
const (
	RelayKeyHeader      = "X-Qeet-Relay-Key"
	RelayClientIPHeader = "X-Qeet-Client-IP"
)

// relayKeys holds the SHA-256 of each configured relay key (nil: no relay is
// trusted). Written once at startup (SetRelayKeys), read on every request.
var relayKeys atomic.Pointer[[][sha256.Size]byte]

// SetRelayKeys declares the keys trusted relays present (RELAY_KEYS). Empty
// keys are skipped; none means no relay is trusted. Call it from the
// composition root before serving.
func SetRelayKeys(keys []string) {
	var sums [][sha256.Size]byte
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			sums = append(sums, sha256.Sum256([]byte(k)))
		}
	}
	relayKeys.Store(&sums)
}

// relayedClientIP is the address a trusted relay says it is relaying for, or
// "" when the request carries no valid relay key or no readable address.
func relayedClientIP(r *http.Request) string {
	claimed := strings.TrimSpace(r.Header.Get(RelayClientIPHeader))
	key := r.Header.Get(RelayKeyHeader)
	if claimed == "" || key == "" {
		return ""
	}
	sums := relayKeys.Load()
	if sums == nil || len(*sums) == 0 {
		return ""
	}
	got := sha256.Sum256([]byte(key))
	trusted := 0
	for _, want := range *sums {
		trusted |= subtle.ConstantTimeCompare(got[:], want[:])
	}
	if trusted != 1 {
		return ""
	}
	addr, err := netip.ParseAddr(claimed)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// ViaTrustedRelay reports whether the request came from a trusted relay that
// named the person's address.
func ViaTrustedRelay(r *http.Request) bool { return relayedClientIP(r) != "" }

const ctxKeyClientIP ctxKey = "qeet.client_ip"

// ClientIPContext puts the request's client address (ClientIP) in its context,
// for code that has the context but not the request, such as an audit record
// written deep in a service.
func ClientIPContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, ClientIP(r))))
	})
}

// ClientIPFromContext is the address ClientIPContext stored ("" when none).
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(ctxKeyClientIP).(string)
	return ip
}
