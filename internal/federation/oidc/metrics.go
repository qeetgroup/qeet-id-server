package oidc

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// tokenRequests counts token endpoint requests by grant and outcome: issued, refused (an RFC 6749
// error answer, the client's to fix) or error (a server failure, answered 500).
var tokenRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "oauth_token_requests_total",
	Help: "Token endpoint requests by grant (authorization_code, refresh_token, token_exchange, device_code, ciba, client_credentials, none, other) and outcome (issued, refused, error).",
}, []string{"grant", "outcome"})

// grantLabel is grantType as a bounded label: a grant this server knows, "none" or "other".
func grantLabel(grantType string) string {
	switch grantType {
	case "authorization_code", "refresh_token", grantTypeClientCredentials:
		return grantType
	case grantTypeTokenExchange:
		return "token_exchange"
	case grantTypeDeviceCode:
		return "device_code"
	case grantTypeCIBA:
		return "ciba"
	case "":
		return "none"
	}
	return "other"
}

// tokenOutcome is "error" for a failure writeTokenError answers with 500, else "refused".
func tokenOutcome(err error) string {
	var oe *oauthError
	if errors.As(err, &oe) {
		return "refused"
	}
	if e := errs.As(err); e == nil || e.Code == errs.CodeInternal {
		return "error"
	}
	return "refused"
}
