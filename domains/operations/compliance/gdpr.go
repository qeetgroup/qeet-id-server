// Package gdpr handles right-to-erasure requests. A request enters with
// a grace period; a background job purges PII once the grace expires.
// PII is replaced with a redacted marker so audit references remain intact.
package gdpr

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

type Request struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	UserID      uuid.UUID  `json:"user_id"`
	RequestedBy *uuid.UUID `json:"requested_by"`
	Reason      *string    `json:"reason"`
	Status      string     `json:"status"`
	GraceUntil  time.Time  `json:"grace_until"`
	CompletedAt *time.Time `json:"completed_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Service struct {
	pool  *pgxpool.Pool
	grace time.Duration
}

func NewService(pool *pgxpool.Pool, grace time.Duration) *Service {
	if grace <= 0 {
		grace = 30 * 24 * time.Hour
	}
	return &Service{pool: pool, grace: grace}
}

type CreateInput struct {
	TenantID uuid.UUID  `json:"tenant_id"`
	UserID   uuid.UUID  `json:"user_id"`
	Reason   string     `json:"reason"`
	By       *uuid.UUID `json:"-"`
}

func (s *Service) Request(ctx context.Context, in CreateInput) (*Request, error) {
	var r Request
	var reason any
	if in.Reason != "" {
		reason = in.Reason
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO "user".purge_requests (tenant_id, user_id, requested_by, reason, grace_until)
		VALUES ($1, $2, $3, $4, NOW() + $5::interval)
		RETURNING id, tenant_id, user_id, requested_by, reason, status, grace_until, completed_at, created_at
	`, in.TenantID, in.UserID, in.By, reason, formatInterval(s.grace)).
		Scan(&r.ID, &r.TenantID, &r.UserID, &r.RequestedBy, &r.Reason, &r.Status, &r.GraceUntil, &r.CompletedAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Service) Cancel(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `UPDATE "user".purge_requests SET status = 'cancelled' WHERE id = $1 AND status = 'pending'`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Request, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, requested_by, reason, status, grace_until, completed_at, created_at
		FROM "user".purge_requests WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		if err := rows.Scan(&r.ID, &r.TenantID, &r.UserID, &r.RequestedBy, &r.Reason, &r.Status, &r.GraceUntil, &r.CompletedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Run is the background sweeper. It picks ripe purge requests and erases
// PII from the user row + drops auth credentials. Audit rows are kept.
func (s *Service) Run(ctx context.Context) {
	tk := time.NewTicker(time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if err := s.tick(ctx); err != nil {
				slog.Warn("gdpr tick", "err", err)
			}
		}
	}
}

// Sweep runs a single purge pass over ripe requests — the same work Run does on
// each tick. Exposed for ops-triggered purges and tests.
func (s *Service) Sweep(ctx context.Context) error { return s.tick(ctx) }

func (s *Service) tick(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id FROM "user".purge_requests
		WHERE status = 'pending' AND grace_until <= NOW()
		LIMIT 50 FOR UPDATE SKIP LOCKED
	`)
	if err != nil {
		return err
	}
	type ent struct {
		ID, UserID uuid.UUID
	}
	var batch []ent
	for rows.Next() {
		var e ent
		if err := rows.Scan(&e.ID, &e.UserID); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, e)
	}
	rows.Close()
	for _, e := range batch {
		if err := s.purgeOne(ctx, e.ID, e.UserID); err != nil {
			slog.Warn("gdpr purge", "user", e.UserID, "err", err)
		}
	}
	return nil
}

func (s *Service) purgeOne(ctx context.Context, requestID, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		UPDATE "user".users
		SET email = 'redacted-' || id::text || '@gdpr.invalid',
		    phone = NULL, display_name = NULL,
		    metadata = '{}'::jsonb,
		    email_verified_at = NULL, phone_verified_at = NULL,
		    status = 'deleted', deleted_at = COALESCE(deleted_at, NOW()),
		    updated_at = NOW()
		WHERE id = $1
	`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.password_credentials WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE "user".purge_requests SET status = 'completed', completed_at = NOW() WHERE id = $1
	`, requestID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func formatInterval(d time.Duration) string {
	seconds := int64(d.Seconds())
	return time.Duration(seconds * int64(time.Second)).String()
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/gdpr/purge", h.create)
	r.Get("/tenants/{tenantID}/gdpr/purge", h.list)
	r.Delete("/gdpr/purge/{id}", h.cancel)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		in.By = p.UserID
	}
	req, err := h.Service.Request(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Cancel(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
