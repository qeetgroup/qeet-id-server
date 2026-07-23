package ratelimit

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Override holds per-tenant rate and capacity for one limit_key.
type Override struct {
	Rate     float64
	Capacity int
}

// TenantLimiter is a tenant-aware version of Limiter: it applies per-tenant
// overrides from DB when present, falling back to the platform defaults.
// Overrides are cached in memory and refreshed on writes via SetOverride.
type TenantLimiter struct {
	store   Store
	defRate float64
	defCap  float64
	pool    *pgxpool.Pool
	key     string // limit_key value stored in DB ("tenant", "user", "api_key")

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

// LoadOverrides fetches all overrides from DB into memory. Called at server startup.
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
		if err := rows.Scan(&tid, &o.Rate, &o.Capacity); err == nil {
			m[tid] = o
		}
	}
	l.mu.Lock()
	l.overrides = m
	l.mu.Unlock()
}

// SetOverride stores or removes an override both in DB and in-memory cache.
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
	l.mu.Lock()
	l.overrides[tenantID] = Override{Rate: rate, Capacity: capacity}
	l.mu.Unlock()
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
	l.mu.Lock()
	delete(l.overrides, tenantID)
	l.mu.Unlock()
	return nil
}

// GetAll returns the default and all tenant-specific overrides for this key.
func (l *TenantLimiter) GetAll(ctx context.Context, pool *pgxpool.Pool) ([]TenantLimit, error) {
	rows, err := pool.Query(ctx, `
		SELECT tenant_id, rate, capacity FROM platform.rate_limit_overrides WHERE limit_key = $1
	`, l.key)
	if err != nil && err != pgx.ErrNoRows {
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

// MiddlewareBy applies the tenant-aware limiter using the given key extractor
// to get both the bucket key string and the tenant UUID for override lookup.
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
				w.WriteHeader(http.StatusTooManyRequests)
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
