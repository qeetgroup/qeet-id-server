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

// Override holds per-organization rate and capacity for one limit_key.
type Override struct {
	Rate     float64
	Capacity int
}

// OrganizationLimiter is a limiter whose rate and capacity can be overridden per
// organization. Overrides for its limit key are cached in memory: LoadOverrides fills
// the cache and the other override methods keep it current.
type OrganizationLimiter struct {
	store   Store
	defRate float64
	defCap  float64
	pool    *pgxpool.Pool
	key     string

	mu        sync.RWMutex
	overrides map[uuid.UUID]Override
}

// NewOrganizationLimiter creates a OrganizationLimiter. Call LoadOverrides after startup.
func NewOrganizationLimiter(store Store, defRate float64, defCap int, pool *pgxpool.Pool, key string) *OrganizationLimiter {
	return &OrganizationLimiter{
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
func (l *OrganizationLimiter) LoadOverrides(ctx context.Context) {
	rows, err := l.pool.Query(ctx, `
		SELECT organization_id, rate, capacity FROM platform.rate_limit_overrides WHERE limit_key = $1
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
			// Silently skipping a row reverts that organization to the platform
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
func ReloadEvery(ctx context.Context, interval time.Duration, limiters ...*OrganizationLimiter) {
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

// SetOverride upserts organizationID's override in the database and the cache.
func (l *OrganizationLimiter) SetOverride(ctx context.Context, organizationID uuid.UUID, rate float64, capacity int) error {
	_, err := l.pool.Exec(ctx, `
		INSERT INTO platform.rate_limit_overrides (organization_id, limit_key, rate, capacity, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (organization_id, limit_key) DO UPDATE SET
			rate = EXCLUDED.rate, capacity = EXCLUDED.capacity, updated_at = NOW()
	`, organizationID, l.key, rate, capacity)
	if err != nil {
		return err
	}
	l.ApplyOverride(organizationID, rate, capacity)
	return nil
}

// DeleteOverride removes the per-organization override, reverting to the default.
func (l *OrganizationLimiter) DeleteOverride(ctx context.Context, organizationID uuid.UUID) error {
	_, err := l.pool.Exec(ctx, `
		DELETE FROM platform.rate_limit_overrides WHERE organization_id = $1 AND limit_key = $2
	`, organizationID, l.key)
	if err != nil {
		return err
	}
	l.ClearOverride(organizationID)
	return nil
}

// ApplyOverride updates only the in-memory cache after a caller-owned database
// transaction commits.
func (l *OrganizationLimiter) ApplyOverride(organizationID uuid.UUID, rate float64, capacity int) {
	l.mu.Lock()
	l.overrides[organizationID] = Override{Rate: rate, Capacity: capacity}
	l.mu.Unlock()
}

// ClearOverride removes only the cached value after a caller-owned delete commits.
func (l *OrganizationLimiter) ClearOverride(organizationID uuid.UUID) {
	l.mu.Lock()
	delete(l.overrides, organizationID)
	l.mu.Unlock()
}

// GetAll returns every organization override for this limiter's key, read from pool.
func (l *OrganizationLimiter) GetAll(ctx context.Context, pool *pgxpool.Pool) ([]OrganizationLimit, error) {
	rows, err := pool.Query(ctx, `
		SELECT organization_id, rate, capacity FROM platform.rate_limit_overrides WHERE limit_key = $1
	`, l.key)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	defer rows.Close()
	out := []OrganizationLimit{}
	for rows.Next() {
		var tl OrganizationLimit
		if err := rows.Scan(&tl.OrganizationID, &tl.Rate, &tl.Capacity); err != nil {
			return nil, err
		}
		out = append(out, tl)
	}
	return out, rows.Err()
}

// OrganizationLimit is one organization's override, as listed by GetAll.
type OrganizationLimit struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Rate           float64   `json:"rate"`
	Capacity       int       `json:"capacity"`
}

func (l *OrganizationLimiter) rateFor(organizationID uuid.UUID) (rate, cap float64) {
	l.mu.RLock()
	o, ok := l.overrides[organizationID]
	l.mu.RUnlock()
	if ok {
		return o.Rate, float64(o.Capacity)
	}
	return l.defRate, l.defCap
}

// MiddlewareBy limits requests by extract's key at the principal's organization rate
// (or the default). It fails open on a store error and answers 429 with
// Retry-After.
func (l *OrganizationLimiter) MiddlewareBy(scopeName string, extract KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := extract(r)
			if id == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Determine per-organization rate by parsing the organization from the principal.
			var organizationID uuid.UUID
			if p := principalOrganizationID(r); p != uuid.Nil {
				organizationID = p
			}
			rate, cap := l.rateFor(organizationID)
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

func principalOrganizationID(r *http.Request) uuid.UUID {
	s := PerOrganization(r)
	if s == "" {
		return uuid.Nil
	}
	id, _ := uuid.Parse(s)
	return id
}
