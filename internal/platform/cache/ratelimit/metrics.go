package ratelimit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// rejections counts requests a limiter answered 429, by its scope (login-ip, token-ip,
// organization, user, apikey, …): a fixed set the router names, never a caller's key.
var rejections = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "rate_limit_rejections_total",
	Help: "Requests answered 429 Too Many Requests, by limiter scope.",
}, []string{"scope"})
