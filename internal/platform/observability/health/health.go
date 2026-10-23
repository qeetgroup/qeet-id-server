// Package health serves the liveness (/healthz), readiness (/readyz) and
// /version endpoints. Liveness always returns 200; readiness runs every
// registered check under one 2s timeout and returns 503 if any fails, or once
// the server has begun to drain for shutdown.
package health

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/buildinfo"
)

// Check is a single readiness probe. It must return promptly (it shares a
// 2 s timeout with the rest of the checks) and return nil when the
// dependency is healthy.
type Check func(ctx context.Context) error

type namedCheck struct {
	name string
	fn   Check
}

// Handler serves the health endpoints. ServiceProfile (dev/test/staging, empty
// elsewhere) is added to the liveness body when set; Schema, the migration found
// at startup, is reported by /version when non-nil.
type Handler struct {
	ServiceName    string
	ServiceEnv     string
	ServiceProfile string
	StartedAt      time.Time
	Build          buildinfo.Info
	Schema         *migrations.Status

	draining atomic.Bool

	checks []namedCheck
}

// New returns a Handler carrying this binary's build metadata.
func New(serviceName, serviceEnv string, startedAt time.Time) *Handler {
	return &Handler{
		ServiceName: serviceName,
		ServiceEnv:  serviceEnv,
		StartedAt:   startedAt,
		Build:       buildinfo.Get(),
	}
}

// AddReadiness registers a dependency check evaluated on every /readyz hit.
func (h *Handler) AddReadiness(name string, c Check) {
	h.checks = append(h.checks, namedCheck{name: name, fn: c})
}

// Liveness always returns 200 with service metadata. See package docs.
func (h *Handler) Liveness(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"status":  "ok",
		"service": h.ServiceName,
		"env":     h.ServiceEnv,
		"uptime":  time.Since(h.StartedAt).String(),
		"build":   h.Build,
	}
	if h.ServiceProfile != "" {
		body["profile"] = h.ServiceProfile
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// Version answers "what's running here": the build's version, commit and date,
// and the database migration it runs on next to the newest this build carries.
// It reads nothing at request time.
func (h *Handler) Version(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"version":    h.Build.Version,
		"commit":     h.Build.Commit,
		"date":       h.Build.Date,
		"go_version": h.Build.GoVersion,
	}
	if h.Schema != nil {
		body["schema"] = map[string]any{"migration": h.Schema.Database, "latest": h.Schema.Latest}
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// Drain makes readiness answer 503 from now on, so a load balancer sends no
// new requests while the server finishes the ones it has.
func (h *Handler) Drain() { h.draining.Store(true) }

// Readiness runs every registered check under a 2 s timeout and returns
// 503 with a per-check breakdown if any one fails, or 503 while draining.
func (h *Handler) Readiness(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
		return
	}
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
