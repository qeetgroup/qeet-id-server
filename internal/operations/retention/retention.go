// Package retention enforces per-tenant data-retention policy. Currently it
// permanently purges soft-deleted users once they're older than the tenant's
// retention window. It is opt-in per tenant (disabled by default) so the
// background sweeper never deletes data a tenant hasn't explicitly allowed.
package retention

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/retention/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const sweepInterval = time.Hour

// Policy is a tenant's retention policy.
// UpdatedAt and UpdatedBy say when, and by whom, it was last changed; nil
// until the tenant sets one.
type Policy struct {
	DeletedUsersEnabled bool       `json:"deleted_users_enabled"`
	DeletedUsersDays    int        `json:"deleted_users_days"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
	UpdatedBy           *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedByEmail      *string    `json:"updated_by_email,omitempty"`
}

// DefaultPolicy is the policy of a tenant that has set none.
func DefaultPolicy() Policy { return Policy{DeletedUsersEnabled: false, DeletedUsersDays: 30} }

func clampDays(d int) int {
	if d < 1 {
		return 1
	}
	if d > 3650 {
		return 3650
	}
	return d
}

// Service stores each tenant's retention policy and enforces it.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the retention policy service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// Get returns the tenant's retention policy.
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	row, err := s.q.GetRetentionPolicy(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		def := DefaultPolicy()
		return &def, nil
	}
	if err != nil {
		return nil, err
	}
	p := &Policy{
		DeletedUsersEnabled: row.DeletedUsersEnabled,
		DeletedUsersDays:    int(row.DeletedUsersDays),
		UpdatedAt:           &row.UpdatedAt,
		UpdatedByEmail:      row.UpdatedByEmail,
	}
	if row.UpdatedBy.Valid {
		by := uuid.UUID(row.UpdatedBy.Bytes)
		p.UpdatedBy = &by
	}
	return p, nil
}

// Update stores the tenant's retention policy, as changed by by (nil: no one
// in particular).
func (s *Service) Update(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, p Policy, by *uuid.UUID) (*Policy, error) {
	p.DeletedUsersDays = clampDays(p.DeletedUsersDays)
	var updatedBy pgtype.UUID
	if by != nil {
		updatedBy = pgtype.UUID{Bytes: *by, Valid: true}
	}
	row, err := s.q.WithTx(tx).UpsertRetentionPolicy(ctx, dbgen.UpsertRetentionPolicyParams{
		TenantID:            tenantID,
		DeletedUsersEnabled: p.DeletedUsersEnabled,
		DeletedUsersDays:    int32(p.DeletedUsersDays), // #nosec G115 -- clamped to 1–3650 by clampDays
		UpdatedBy:           updatedBy,
	})
	if err != nil {
		return nil, err
	}
	p.DeletedUsersEnabled = row.DeletedUsersEnabled
	p.DeletedUsersDays = int(row.DeletedUsersDays)
	p.UpdatedAt, p.UpdatedBy, p.UpdatedByEmail = &row.UpdatedAt, by, nil
	return &p, nil
}

// RipeDeletedUsers counts soft-deleted users older than `days` for a tenant —
// i.e. how many a purge would remove right now.
func (s *Service) RipeDeletedUsers(ctx context.Context, tenantID uuid.UUID, days int) (int, error) {
	// "user".users.tenant_id is NOT NULL UUID; sqlc infers pgtype.UUID here due
	// to the quoted "user" schema — pass Valid: true to match a non-null value.
	n, err := s.q.CountRipeDeletedUsers(ctx, dbgen.CountRipeDeletedUsersParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Days:     int32(clampDays(days)), // #nosec G115 -- clamped to 1–3650 by clampDays
	})
	return int(n), err
}

// purgeListSize is how many ripe users PurgeTenant lists at a time.
const purgeListSize = 500

// userPurgeFailures counts deleted accounts the purge could not remove.
var userPurgeFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "retention_user_purge_failures_total",
	Help: "Deleted accounts the retention purge failed to remove for good; each is tried again at the next run.",
})

// PurgeTenant permanently deletes soft-deleted users past the window, one at
// a time, and returns the number purged. A user whose deletion fails is
// counted in retention_user_purge_failures_total and left for the next run;
// the others are still purged.
func (s *Service) PurgeTenant(ctx context.Context, tenantID uuid.UUID, days int) (int, error) {
	// See RipeDeletedUsers for the pgtype.UUID note.
	tenant := pgtype.UUID{Bytes: tenantID, Valid: true}
	window := int32(clampDays(days)) // #nosec G115 -- clamped to 1–3650 by clampDays
	purged, after := 0, uuid.Nil
	for {
		ids, err := s.q.ListRipeDeletedUsers(ctx, dbgen.ListRipeDeletedUsersParams{
			TenantID: tenant, Days: window, After: after, MaxRows: purgeListSize,
		})
		if err != nil {
			return purged, err
		}
		for _, id := range ids {
			n, err := s.q.PurgeRipeDeletedUser(ctx, dbgen.PurgeRipeDeletedUserParams{ID: id, TenantID: tenant, Days: window})
			if ctx.Err() != nil {
				return purged, ctx.Err()
			}
			if err != nil {
				userPurgeFailures.Inc()
				slog.Warn("retention: purge a deleted user", "tenant", tenantID, "user", id, "err", err)
				continue
			}
			purged += int(n)
		}
		if len(ids) < purgeListSize {
			return purged, nil
		}
		after = ids[len(ids)-1]
	}
}

// sweep purges ripe users for every tenant that has the policy enabled.
func (s *Service) sweep(ctx context.Context) error {
	policies, err := s.q.ListEnabledRetentionPolicies(ctx)
	if err != nil {
		return err
	}
	for _, p := range policies {
		days := clampDays(int(p.DeletedUsersDays))
		n, err := s.PurgeTenant(ctx, p.TenantID, days)
		if n > 0 {
			slog.Info("retention sweep purged users", "tenant", p.TenantID, "count", n)
			if err := s.recordSweep(ctx, p.TenantID, n, days); err != nil {
				slog.Warn("retention sweep: record the purge", "tenant", p.TenantID, "err", err)
			}
		}
		if err != nil {
			slog.Warn("retention sweep", "tenant", p.TenantID, "err", err)
		}
	}
	return nil
}

// recordSweep records in the tenant's audit trail, as the system, that the
// sweep purged n deleted users older than days, as a manual run is recorded.
func (s *Service) recordSweep(ctx context.Context, tenantID uuid.UUID, n, days int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "system",
		Action: "retention.purge_run", ResourceType: "retention_policy",
		Metadata: map[string]any{"purged": n, "deleted_users_days": days},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Run is the background sweeper, registered as a worker. Only acts on tenants
// that have explicitly enabled retention.
func (s *Service) Run(ctx context.Context) {
	tk := time.NewTicker(sweepInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if err := s.sweep(ctx); err != nil {
				slog.Warn("retention sweep", "err", err)
			}
		}
	}
}

// Handler serves the retention policy HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the retention policy routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/retention", h.get)
	r.Put("/tenants/{tenantID}/retention", h.update)
	r.Post("/tenants/{tenantID}/retention/preview", h.preview)
	r.Post("/tenants/{tenantID}/retention/run", h.run)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrRetentionTenantInvalid, errs.ErrRetentionTenantMismatch)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Get(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in Policy
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	actorID, actorType := audit.ActorOf(r).Identity()
	p, err := h.Service.Update(ctx, tx, tenantID, in, actorID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "retention.policy_updated", ResourceType: "retention_policy",
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"deleted_users_enabled": p.DeletedUsersEnabled, "deleted_users_days": p.DeletedUsersDays},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) preview(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Get(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.RipeDeletedUsers(r.Context(), tenantID, p.DeletedUsersDays)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ripe_deleted_users": n, "deleted_users_days": p.DeletedUsersDays})
}

func (h *Handler) run(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Get(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	n, err := h.Service.PurgeTenant(ctx, tenantID, p.DeletedUsersDays)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if n > 0 {
		tx, err := h.Service.Pool().Begin(ctx)
		if err == nil {
			defer tx.Rollback(ctx)
			actorID, actorType := audit.ActorOf(r).Identity()
			tid := tenantID
			if aerr := audit.Record(ctx, tx, audit.Event{
				TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
				Action: "retention.purge_run", ResourceType: "retention_policy",
				IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
				Metadata: map[string]any{"purged": n, "deleted_users_days": p.DeletedUsersDays},
			}); aerr == nil {
				_ = tx.Commit(ctx)
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"purged": n})
}
