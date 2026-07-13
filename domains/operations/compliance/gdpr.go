// Package gdpr handles right-to-erasure requests. A request enters with
// a grace period; a background job purges PII once the grace expires.
// PII is replaced with a redacted marker so audit references remain intact.
package gdpr

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
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
			if err := s.exportSweepTick(ctx); err != nil {
				slog.Warn("gdpr export tick", "err", err)
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

// ExportRequest is a queued/completed GDPR data-export job. Payload is filled
// in by the background sweep (exportTick) once status flips to "ready".
type ExportRequest struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	UserID      uuid.UUID      `json:"user_id"`
	RequestedBy *uuid.UUID     `json:"requested_by"`
	Status      string         `json:"status"`
	Payload     map[string]any `json:"payload,omitempty"`
	Error       *string        `json:"error,omitempty"`
	CompletedAt *time.Time     `json:"completed_at"`
	CreatedAt   time.Time      `json:"created_at"`
}

type ExportInput struct {
	TenantID uuid.UUID  `json:"tenant_id"`
	UserID   uuid.UUID  `json:"user_id"`
	By       *uuid.UUID `json:"-"`
}

// RequestExport queues a data-export job for a user. The background sweep
// (exportTick) builds the payload asynchronously; poll GetExport for status.
func (s *Service) RequestExport(ctx context.Context, in ExportInput) (*ExportRequest, error) {
	var r ExportRequest
	err := s.pool.QueryRow(ctx, `
		INSERT INTO "user".export_requests (tenant_id, user_id, requested_by)
		VALUES ($1, $2, $3)
		RETURNING id, tenant_id, user_id, requested_by, status, completed_at, created_at
	`, in.TenantID, in.UserID, in.By).
		Scan(&r.ID, &r.TenantID, &r.UserID, &r.RequestedBy, &r.Status, &r.CompletedAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListExports returns a tenant's export requests, most recent first.
func (s *Service) ListExports(ctx context.Context, tenantID uuid.UUID) ([]ExportRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, requested_by, status, error, completed_at, created_at
		FROM "user".export_requests WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ExportRequest, 0)
	for rows.Next() {
		var r ExportRequest
		if err := rows.Scan(&r.ID, &r.TenantID, &r.UserID, &r.RequestedBy, &r.Status, &r.Error, &r.CompletedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetExport fetches one export request, including its payload once ready.
func (s *Service) GetExport(ctx context.Context, tenantID, id uuid.UUID) (*ExportRequest, error) {
	var r ExportRequest
	var payload []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, requested_by, status, payload, error, completed_at, created_at
		FROM "user".export_requests WHERE id = $1 AND tenant_id = $2
	`, id, tenantID).
		Scan(&r.ID, &r.TenantID, &r.UserID, &r.RequestedBy, &r.Status, &payload, &r.Error, &r.CompletedAt, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &r.Payload); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

// exportSweepTick picks pending export requests and builds their payload.
// Runs on the same ticker cadence as the purge sweep (see Run).
func (s *Service) exportSweepTick(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id FROM "user".export_requests
		WHERE status = 'pending'
		LIMIT 20 FOR UPDATE SKIP LOCKED
	`)
	if err != nil {
		return err
	}
	type ent struct{ ID, TenantID, UserID uuid.UUID }
	var batch []ent
	for rows.Next() {
		var e ent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.UserID); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, e)
	}
	rows.Close()
	for _, e := range batch {
		if err := s.buildExport(ctx, e.ID, e.TenantID, e.UserID); err != nil {
			slog.Warn("gdpr export", "user", e.UserID, "err", err)
			msg := err.Error()
			_, _ = s.pool.Exec(ctx, `
				UPDATE "user".export_requests SET status = 'failed', error = $2, completed_at = NOW() WHERE id = $1
			`, e.ID, msg)
		}
	}
	return nil
}

func (s *Service) buildExport(ctx context.Context, requestID, tenantID, userID uuid.UUID) error {
	payload, err := s.collectUserData(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE "user".export_requests SET status = 'ready', payload = $2, completed_at = NOW() WHERE id = $1
	`, requestID, raw)
	return err
}

type exportProfile struct {
	Email           string     `json:"email"`
	Phone           *string    `json:"phone,omitempty"`
	DisplayName     *string    `json:"display_name,omitempty"`
	Status          string     `json:"status"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	PhoneVerifiedAt *time.Time `json:"phone_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type exportSession struct {
	ID         uuid.UUID  `json:"id"`
	IP         *string    `json:"ip,omitempty"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type exportPasskey struct {
	ID         uuid.UUID  `json:"id"`
	Name       *string    `json:"name,omitempty"`
	Transports []string   `json:"transports,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type exportRole struct {
	RoleName  string    `json:"role_name"`
	GrantedAt time.Time `json:"granted_at"`
}

// collectUserData assembles the GDPR-portable data for one user: profile,
// sessions, passkey/MFA metadata (no secrets or credential material), and
// role assignments. Password hashes, TOTP secrets, and recovery-code hashes
// are deliberately excluded — they're credentials, not personal data.
func (s *Service) collectUserData(ctx context.Context, tenantID, userID uuid.UUID) (map[string]any, error) {
	var profile exportProfile
	err := s.pool.QueryRow(ctx, `
		SELECT email, phone, display_name, status, email_verified_at, phone_verified_at, created_at
		FROM "user".users WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(&profile.Email, &profile.Phone, &profile.DisplayName, &profile.Status,
		&profile.EmailVerifiedAt, &profile.PhoneVerifiedAt, &profile.CreatedAt)
	if err != nil {
		return nil, err
	}

	sessions := make([]exportSession, 0)
	sRows, err := s.pool.Query(ctx, `
		SELECT id, host(ip), user_agent, created_at, last_seen_at, revoked_at
		FROM auth.sessions WHERE user_id = $1 AND tenant_id = $2 ORDER BY created_at DESC
	`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	for sRows.Next() {
		var sess exportSession
		if err := sRows.Scan(&sess.ID, &sess.IP, &sess.UserAgent, &sess.CreatedAt, &sess.LastSeenAt, &sess.RevokedAt); err != nil {
			sRows.Close()
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	sRows.Close()
	if err := sRows.Err(); err != nil {
		return nil, err
	}

	passkeys := make([]exportPasskey, 0)
	pRows, err := s.pool.Query(ctx, `
		SELECT id, name, transports, created_at, last_used_at
		FROM auth.passkey_credentials WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	for pRows.Next() {
		var pk exportPasskey
		if err := pRows.Scan(&pk.ID, &pk.Name, &pk.Transports, &pk.CreatedAt, &pk.LastUsedAt); err != nil {
			pRows.Close()
			return nil, err
		}
		passkeys = append(passkeys, pk)
	}
	pRows.Close()
	if err := pRows.Err(); err != nil {
		return nil, err
	}

	roles := make([]exportRole, 0)
	rRows, err := s.pool.Query(ctx, `
		SELECT r.name, ur.granted_at
		FROM rbac.user_roles ur
		JOIN rbac.roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2
	`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	for rRows.Next() {
		var role exportRole
		if err := rRows.Scan(&role.RoleName, &role.GrantedAt); err != nil {
			rRows.Close()
			return nil, err
		}
		roles = append(roles, role)
	}
	rRows.Close()
	if err := rRows.Err(); err != nil {
		return nil, err
	}

	var mfaEnabled bool
	err = s.pool.QueryRow(ctx, `
		SELECT confirmed_at IS NOT NULL FROM auth.mfa_totp WHERE user_id = $1
	`, userID).Scan(&mfaEnabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	return map[string]any{
		"profile":          profile,
		"sessions":         sessions,
		"passkeys":         passkeys,
		"roles":            roles,
		"mfa_totp_enabled": mfaEnabled,
		"generated_at":     time.Now().UTC(),
	}, nil
}

func formatInterval(d time.Duration) string {
	seconds := int64(d.Seconds())
	return time.Duration(seconds * int64(time.Second)).String()
}

type Handler struct {
	Service  *Service
	Evidence *EvidenceService
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/gdpr/purge", h.create)
	r.Get("/tenants/{tenantID}/gdpr/purge", h.list)
	r.Delete("/gdpr/purge/{id}", h.cancel)

	r.Post("/gdpr/export", h.createExport)
	r.Get("/tenants/{tenantID}/gdpr/export", h.listExports)
	r.Get("/tenants/{tenantID}/gdpr/export/{id}", h.getExport)

	// Compliance evidence routes — SOC 2 and ISO 27001 live checks.
	h.mountEvidence(r)
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

func (h *Handler) createExport(w http.ResponseWriter, r *http.Request) {
	var in ExportInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		in.By = p.UserID
	}
	req, err := h.Service.RequestExport(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, req)
}

func (h *Handler) listExports(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	out, err := h.Service.ListExports(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// getExport returns the export request; once status is "ready" the response
// includes the full payload with a Content-Disposition download header.
func (h *Handler) getExport(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	out, err := h.Service.GetExport(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if out.Status == "ready" {
		w.Header().Set("Content-Disposition", `attachment; filename="export-`+out.ID.String()+`.json"`)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
