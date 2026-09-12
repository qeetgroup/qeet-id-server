// Package db owns the single pgx pool shared by every module.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

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

	// Server-side safety valves, applied to every connection in the pool.
	//
	// HTTP_WRITE_TIMEOUT closes the *client* connection but does not cancel the
	// query: Postgres keeps executing and the pool slot stays occupied. With
	// DB_MAX_CONNS defaulting to 10, a handful of pathological queries (a
	// missing index, a large OFFSET, an unbounded scan) can occupy the entire
	// pool and take the API down while every statement is individually
	// "correct". These bound the blast radius in the database itself, where the
	// work actually happens.
	//
	// Set via RuntimeParams so they are sent at connection setup and cannot be
	// forgotten at a call site. Any value already present in DATABASE_URL wins,
	// so an operator can still tune per-environment without a code change.
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
