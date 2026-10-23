package ratelimit

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Override holds per-tenant rate and capacity for one limit_key.
type Override struct {
	Rate     float64
	Capacity int
}

// TenantLimiter is a limiter whose rate and capacity can be overridden per
// tenant. Overrides for its limit key are cached in memory: LoadOverrides fills
// the cache and the other override methods keep it current.
type TenantLimiter struct {
	store   Store
	defRate float64
	defCap  float64
	pool    *pgxpool.Pool
	key     string

	mu        sync.RWMutex
	overrides map[uuid.UUID]Override
}

// NewTenantLimiter creates a TenantLimiter. Call LoadOverrides after startup.
func NewTenantLimiter(store Store, defRate float64, defCap int, pool *pgxpool.Pool, key string) *TenantLimiter {
	return &TenantLimiter{
		store:     store,
		defRate:   defRate,
		defCap:    float64(defCap),
		pool:      pool,
		key:       key,
		overrides: make(map[uuid.UUID]Override),
	}
}

// LoadOverrides replaces the cache with the database's overrides. On a read
// error it logs and keeps the previous cache.
func (l *TenantLimiter) LoadOverrides(ctx context.Context) {
	rows, err := l.pool.Query(ctx, `
		SELECT tenant_id, rate, capacity FROM platform.rate_limit_overrides WHERE limit_key = $1
	`, l.key)
	if err != nil {
		slog.Warn("ratelimit: could not load overrides", "key", l.key, "err", err)
		return
	}
	defer rows.Close()
	m := make(map[uuid.UUID]Override)
	for rows.Next() {
		var tid uuid.UUID
		var o Override
		if err := rows.Scan(&tid, &o.Rate, &o.Capacity); err != nil {
			// Silently skipping a row reverts that tenant to the platform
			// default with no signal. Abandon the refresh and keep the previous
			// snapshot rather than installing a partial one.
			slog.Warn("ratelimit: could not scan override", "key", l.key, "err", err)
			return
		}
		m[tid] = o
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ratelimit: override read truncated", "key", l.key, "err", err)
		return
	}
	l.mu.Lock()
	l.overrides = m
	l.mu.Unlock()
}

// ReloadEvery reloads each limiter's overrides every interval until ctx ends,
// so a change made through another instance, or its reset, takes effect here.
func ReloadEvery(ctx context.Context, interval time.Duration, limiters ...*TenantLimiter) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, l := range limiters {
				l.LoadOverrides(ctx)
			}
		}
	}
}

// SetOverride upserts tenantID's override in the database and the cache.
func (l *TenantLimiter) SetOverride(ctx context.Context, tenantID uuid.UUID, rate float64, capacity int) error {
	_, err := l.pool.Exec(ctx, `
		INSERT INTO platform.rate_limit_overrides (tenant_id, limit_key, rate, capacity, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (tenant_id, limit_key) DO UPDATE SET
			rate = EXCLUDED.rate, capacity = EXCLUDED.capacity, updated_at = NOW()
	`, tenantID, l.key, rate, capacity)
	if err != nil {
		return err
	}
	l.ApplyOverride(tenantID, rate, capacity)
	return nil
}

// DeleteOverride removes the per-tenant override, reverting to the default.
func (l *TenantLimiter) DeleteOverride(ctx context.Context, tenantID uuid.UUID) error {
	_, err := l.pool.Exec(ctx, `
		DELETE FROM platform.rate_limit_overrides WHERE tenant_id = $1 AND limit_key = $2
	`, tenantID, l.key)
	if err != nil {
		return err
	}
	l.ClearOverride(tenantID)
	return nil
}

// ApplyOverride updates only the in-memory cache after a caller-owned database
// transaction commits.
func (l *TenantLimiter) ApplyOverride(tenantID uuid.UUID, rate float64, capacity int) {
	l.mu.Lock()
	l.overrides[tenantID] = Override{Rate: rate, Capacity: capacity}
	l.mu.Unlock()
}

// ClearOverride removes only the cached value after a caller-owned delete commits.
func (l *TenantLimiter) ClearOverride(tenantID uuid.UUID) {
	l.mu.Lock()
	delete(l.overrides, tenantID)
	l.mu.Unlock()
}

// GetAll returns every tenant override for this limiter's key, read from pool.
func (l *TenantLimiter) GetAll(ctx context.Context, pool *pgxpool.Pool) ([]TenantLimit, error) {
	rows, err := pool.Query(ctx, `
		SELECT tenant_id, rate, capacity FROM platform.rate_limit_overrides WHERE limit_key = $1
	`, l.key)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	defer rows.Close()
	out := []TenantLimit{}
	for rows.Next() {
		var tl TenantLimit
		if err := rows.Scan(&tl.TenantID, &tl.Rate, &tl.Capacity); err != nil {
			return nil, err
		}
		out = append(out, tl)
	}
	return out, rows.Err()
}

// TenantLimit is one tenant's override, as listed by GetAll.
type TenantLimit struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Rate     float64   `json:"rate"`
	Capacity int       `json:"capacity"`
}

func (l *TenantLimiter) rateFor(tenantID uuid.UUID) (rate, cap float64) {
	l.mu.RLock()
	o, ok := l.overrides[tenantID]
	l.mu.RUnlock()
	if ok {
		return o.Rate, float64(o.Capacity)
	}
	return l.defRate, l.defCap
}

// MiddlewareBy limits requests by extract's key at the principal's tenant rate
// (or the default). It fails open on a store error and answers 429 with
// Retry-After.
func (l *TenantLimiter) MiddlewareBy(scopeName string, extract KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := extract(r)
			if id == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Determine per-tenant rate by parsing the tenant from the principal.
			var tenantID uuid.UUID
			if p := principalTenantID(r); p != uuid.Nil {
				tenantID = p
			}
			rate, cap := l.rateFor(tenantID)
			allowed, retry, err := l.store.Take(r.Context(), scopeName+":"+id, rate, cap)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				// Write the standard error envelope, not a bare status, so clients get a
				// code to branch on.
				httpx.WriteError(w, r, errs.ErrTooManyRequests.WithMetadata(
					map[string]any{"retry_after": retry}))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func principalTenantID(r *http.Request) uuid.UUID {
	s := PerTenant(r)
	if s == "" {
		return uuid.Nil
	}
	id, _ := uuid.Parse(s)
	return id
}
