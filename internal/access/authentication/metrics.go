package authentication

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// signIns counts sign-ins by method and outcome: "succeeded" once the session (and its
// auth.login_succeeded row) commits, or the Failure* reason of a refused one. A refusal is the
// expected answer to a wrong credential, not a server error; those surface as 5xx in
// http_requests_total.
var signIns = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sign_ins_total",
	Help: "Sign-ins by method (password, passkey, magic_link, social, saml, oidc_sso, ldap, mfa, …) and outcome: succeeded, or the reason a sign-in was refused.",
}, []string{"method", "outcome"})

// countSignIn counts a committed sign-in by method.
func countSignIn(method string) {
	if method == "" {
		method = "unknown"
	}
	signIns.WithLabelValues(method, "succeeded").Inc()
}
