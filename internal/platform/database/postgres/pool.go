// Package postgres owns the single pgx pool shared by every module.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool opens a pgx pool on url with server-side query timeouts and row-level
// security, applying minConns and maxConns when positive, and returns it once
// a ping succeeds within 5 seconds.
func NewPool(ctx context.Context, url string, minConns, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	if minConns > 0 {
		cfg.MinConns = minConns
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	cfg.MaxConnLifetime = time.Hour
	// Without jitter every connection opened during startup expires in the same
	// second an hour later, producing a synchronized reconnect storm.
	cfg.MaxConnLifetimeJitter = 5 * time.Minute
	cfg.MaxConnIdleTime = 30 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	// Server-side timeouts on every connection: an HTTP timeout doesn't cancel the
	// query, so a few runaway statements could otherwise hold the whole pool. They
	// are sent at connection setup; a value already set in the DB URL wins.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	for k, v := range map[string]string{
		// Long enough for the heaviest legitimate report, short enough that a
		// runaway query frees its connection on its own.
		"statement_timeout": "30000", // 30s
		// A writer waiting on a lock should give up quickly rather than pile up
		// behind one stuck transaction — see the per-tenant audit advisory lock.
		"lock_timeout": "5000", // 5s
		// An abandoned open transaction holds locks and a connection forever.
		"idle_in_transaction_session_timeout": "60000", // 60s
	} {
		if _, ok := cfg.ConnConfig.RuntimeParams[k]; !ok {
			cfg.ConnConfig.RuntimeParams[k] = v
		}
	}

	// Row-level security: every connection runs as AppRole, scoped to the
	// organisation of the context that takes it (see rowsecurity.go).
	cfg.AfterConnect = useAppRole
	cfg.PrepareConn = prepareScope

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return pool, nil
}
