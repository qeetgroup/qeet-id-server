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

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/retention/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	row, err := s.q.GetRetentionPolicy(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		def := DefaultPolicy()
		return &def, nil
	}
	if err != nil {
		return nil, err
	}
	return &Policy{
		DeletedUsersEnabled: row.DeletedUsersEnabled,
		DeletedUsersDays:    int(row.DeletedUsersDays),
	}, nil
}

func (s *Service) Update(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, p Policy) (*Policy, error) {
	p.DeletedUsersDays = clampDays(p.DeletedUsersDays)
	row, err := s.q.WithTx(tx).UpsertRetentionPolicy(ctx, dbgen.UpsertRetentionPolicyParams{
		TenantID:            tenantID,
		DeletedUsersEnabled: p.DeletedUsersEnabled,
		DeletedUsersDays:    int32(p.DeletedUsersDays),
	})
	if err != nil {
		return nil, err
	}
	p.DeletedUsersEnabled = row.DeletedUsersEnabled
	p.DeletedUsersDays = int(row.DeletedUsersDays)
	return &p, nil
}

// RipeDeletedUsers counts soft-deleted users older than `days` for a tenant —
// i.e. how many a purge would remove right now.
func (s *Service) RipeDeletedUsers(ctx context.Context, tenantID uuid.UUID, days int) (int, error) {
	// "user".users.tenant_id is NOT NULL UUID; sqlc infers pgtype.UUID here due
	// to the quoted "user" schema — pass Valid: true to match a non-null value.
	n, err := s.q.CountRipeDeletedUsers(ctx, dbgen.CountRipeDeletedUsersParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Days:     int32(clampDays(days)),
	})
	return int(n), err
}

// PurgeTenant permanently deletes soft-deleted users past the window. Returns
// the number purged.
func (s *Service) PurgeTenant(ctx context.Context, tenantID uuid.UUID, days int) (int, error) {
	// See RipeDeletedUsers for the pgtype.UUID note.
	n, err := s.q.PurgeRipeDeletedUsers(ctx, dbgen.PurgeRipeDeletedUsersParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Days:     int32(clampDays(days)),
	})
	return int(n), err
}

// sweep purges ripe users for every tenant that has the policy enabled.
func (s *Service) sweep(ctx context.Context) error {
	policies, err := s.q.ListEnabledRetentionPolicies(ctx)
	if err != nil {
		return err
	}
	for _, p := range policies {
		n, err := s.PurgeTenant(ctx, p.TenantID, int(p.DeletedUsersDays))
		if err != nil {
			slog.Warn("retention sweep", "tenant", p.TenantID, "err", err)
			continue
		}
		if n > 0 {
			slog.Info("retention sweep purged users", "tenant", p.TenantID, "count", n)
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
