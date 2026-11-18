// Package health serves the liveness (/healthz), readiness (/readyz) and
// /version endpoints. Liveness always returns 200; readiness runs every
// registered check under one 2s timeout and returns 503 if any fails, or once
// the server has begun to drain for shutdown.
package health

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

// New returns a Handler carrying this binary's build metadata.
func New(serviceName, serviceEnv string, startedAt time.Time) *Handler {
	return &Handler{
		ServiceName: serviceName,
		ServiceEnv:  serviceEnv,
		StartedAt:   startedAt,
		Build:       buildinfo.Get(),
	}
}

// PingDB returns a Check that pings the given pgxpool.Pool.
func PingDB(pool *pgxpool.Pool) Check {
	return func(ctx context.Context) error {
		return pool.Ping(ctx)
	}
}
