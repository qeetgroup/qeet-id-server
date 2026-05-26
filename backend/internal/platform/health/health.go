// Package health exposes Kubernetes-shaped liveness and readiness probes.
//
// /healthz reports process aliveness. It returns 200 unconditionally — if
// Go can answer the request at all, the process is alive. Kubernetes uses
// this signal to decide whether to restart the pod.
//
// /readyz runs every registered dependency check with a short shared
// timeout and returns 503 if any check fails. Kubernetes uses this signal
// to decide whether to route traffic to the pod.
package health

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

// Check is a single readiness probe. It must return promptly (it shares a
// 2 s timeout with the rest of the checks) and return nil when the
// dependency is healthy.
type Check func(ctx context.Context) error

type namedCheck struct {
	name string
	fn   Check
}

type Handler struct {
	ServiceName string
	ServiceEnv  string
	StartedAt   time.Time

	checks []namedCheck
}

func New(serviceName, serviceEnv string, startedAt time.Time) *Handler {
	return &Handler{
		ServiceName: serviceName,
		ServiceEnv:  serviceEnv,
		StartedAt:   startedAt,
	}
}

// AddReadiness registers a dependency check evaluated on every /readyz hit.
func (h *Handler) AddReadiness(name string, c Check) {
	h.checks = append(h.checks, namedCheck{name: name, fn: c})
}

// Liveness always returns 200 with service metadata. See package docs.
func (h *Handler) Liveness(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": h.ServiceName,
		"env":     h.ServiceEnv,
		"uptime":  time.Since(h.StartedAt).String(),
	})
}

// Readiness runs every registered check under a 2 s timeout and returns
// 503 with a per-check breakdown if any one fails.
func (h *Handler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	results := make(map[string]string, len(h.checks))
	allOK := true
	for _, c := range h.checks {
		if err := c.fn(ctx); err != nil {
			results[c.name] = "fail: " + err.Error()
			allOK = false
		} else {
			results[c.name] = "ok"
		}
	}

	body := map[string]any{
		"status": "ready",
		"checks": results,
	}
	status := http.StatusOK
	if !allOK {
		body["status"] = "not_ready"
		status = http.StatusServiceUnavailable
	}
	httpx.WriteJSON(w, status, body)
}

// PingDB returns a Check that pings the given pgxpool.Pool.
func PingDB(pool *pgxpool.Pool) Check {
	return func(ctx context.Context) error {
		return pool.Ping(ctx)
	}
}
