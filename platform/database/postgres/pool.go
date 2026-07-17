// Package db owns the single pgx pool shared by every module.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/database/rlsctx"
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
	cfg.HealthCheckPeriod = 30 * time.Second

	// Row-Level-Security scoping. On every connection checkout we stamp the
	// session GUCs the RLS policies read (see migration 0082):
	//
	//   - a request scoped to a specific tenant (a validated {tenantID} route,
	//     stamped into the context by EnforceTenantScope) sets `app.tenant_id`
	//     so policies restrict rows to that tenant;
	//   - everything else (account-level/self-scoped routes, public endpoints,
	//     background workers, the seeder) carries no scoped tenant and runs with
	//     `app.bypass_rls = on`, matching the app's existing model where those
	//     paths scope themselves by user id or operate cross-tenant by design.
	//
	// BeforeAcquire always writes BOTH GUCs, so a connection can never inherit a
	// stale scope from a previous checkout. Because the connection is held
	// exclusively between BeforeAcquire and AfterRelease, a session-level SET is
	// safe under pooling. This is defense-in-depth: it backstops (does not
	// replace) the per-query `WHERE tenant_id = $1` predicates. When connecting
	// as the postgres superuser it is inert (superusers bypass RLS) — enforcement
	// requires the dedicated non-superuser app role.
	cfg.BeforeAcquire = func(ctx context.Context, conn *pgx.Conn) bool {
		tenant, bypass := "", "on"
		if tid, ok := rlsctx.TenantFromContext(ctx); ok {
			tenant, bypass = tid.String(), ""
		}
		if _, err := conn.Exec(ctx,
			"SELECT set_config('app.tenant_id', $1, false), set_config('app.bypass_rls', $2, false)",
			tenant, bypass); err != nil {
			return false // discard a connection we couldn't scope rather than serve it unscoped
		}
		return true
	}
	// Reset to a fail-closed default when a connection returns to the pool, so an
	// idle pooled connection never sits with a tenant scope or a bypass flag set.
	cfg.AfterRelease = func(conn *pgx.Conn) bool {
		resetCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(resetCtx,
			"SELECT set_config('app.tenant_id', '', false), set_config('app.bypass_rls', '', false)"); err != nil {
			return false // drop a connection we couldn't reset
		}
		return true
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
