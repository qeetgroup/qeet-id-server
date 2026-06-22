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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

const sweepInterval = time.Hour

type Policy struct {
	DeletedUsersEnabled bool `json:"deleted_users_enabled"`
	DeletedUsersDays    int  `json:"deleted_users_days"`
}

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

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	var p Policy
	err := s.pool.QueryRow(ctx, `
		SELECT deleted_users_enabled, deleted_users_days FROM tenant.retention_policy WHERE tenant_id = $1
	`, tenantID).Scan(&p.DeletedUsersEnabled, &p.DeletedUsersDays)
	if errors.Is(err, pgx.ErrNoRows) {
		def := DefaultPolicy()
		return &def, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Service) Update(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, p Policy) (*Policy, error) {
	p.DeletedUsersDays = clampDays(p.DeletedUsersDays)
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenant.retention_policy (tenant_id, deleted_users_enabled, deleted_users_days, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			deleted_users_enabled = EXCLUDED.deleted_users_enabled,
			deleted_users_days = EXCLUDED.deleted_users_days,
			updated_at = NOW()
		RETURNING deleted_users_enabled, deleted_users_days
	`, tenantID, p.DeletedUsersEnabled, p.DeletedUsersDays).Scan(&p.DeletedUsersEnabled, &p.DeletedUsersDays); err != nil {
		return nil, err
	}
	return &p, nil
}

// RipeDeletedUsers counts soft-deleted users older than `days` for a tenant —
// i.e. how many a purge would remove right now.
func (s *Service) RipeDeletedUsers(ctx context.Context, tenantID uuid.UUID, days int) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM "user".users
		WHERE tenant_id = $1 AND deleted_at IS NOT NULL
		  AND deleted_at < NOW() - make_interval(days => $2)
	`, tenantID, clampDays(days)).Scan(&n)
	return n, err
}

// PurgeTenant permanently deletes soft-deleted users past the window. Returns
// the number purged.
func (s *Service) PurgeTenant(ctx context.Context, tenantID uuid.UUID, days int) (int, error) {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM "user".users
		WHERE tenant_id = $1 AND deleted_at IS NOT NULL
		  AND deleted_at < NOW() - make_interval(days => $2)
	`, tenantID, clampDays(days))
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// sweep purges ripe users for every tenant that has the policy enabled.
func (s *Service) sweep(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, deleted_users_days FROM tenant.retention_policy WHERE deleted_users_enabled = TRUE
	`)
	if err != nil {
		return err
	}
	type job struct {
		tenant uuid.UUID
		days   int
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.tenant, &j.days); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		n, err := s.PurgeTenant(ctx, j.tenant, j.days)
		if err != nil {
			slog.Warn("retention sweep", "tenant", j.tenant, "err", err)
			continue
		}
		if n > 0 {
			slog.Info("retention sweep purged users", "tenant", j.tenant, "count", n)
		}
	}
	return nil
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

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/retention", h.get)
	r.Put("/tenants/{tenantID}/retention", h.update)
	r.Post("/tenants/{tenantID}/retention/preview", h.preview)
	r.Post("/tenants/{tenantID}/retention/run", h.run)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
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
	p, err := h.Service.Update(ctx, tx, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
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
			actorID, actorType := auditActor(r)
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
