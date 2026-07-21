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

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q     *dbgen.Queries
	grace time.Duration
}

func NewService(pool *pgxpool.Pool, grace time.Duration) *Service {
	if grace <= 0 {
		grace = 30 * 24 * time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), grace: grace}
}

type CreateInput struct {
	TenantID uuid.UUID  `json:"tenant_id"`
	UserID   uuid.UUID  `json:"user_id"`
	Reason   string     `json:"reason"`
	By       *uuid.UUID `json:"-"`
}

func (s *Service) Request(ctx context.Context, in CreateInput) (*Request, error) {
	// grace_until is pre-computed here (instead of NOW() + $5::interval) to
	// avoid the pgtype.Interval parameter type mismatch in sqlc-generated code.
	var reason *string
	if in.Reason != "" {
		reason = &in.Reason
	}
	row, err := s.q.InsertPurgeRequest(ctx, dbgen.InsertPurgeRequestParams{
		TenantID:    in.TenantID,
		UserID:      in.UserID,
		RequestedBy: pgUUIDNullable(in.By),
		Reason:      reason,
		GraceUntil:  time.Now().UTC().Add(s.grace),
	})
	if err != nil {
		return nil, err
	}
	return purgeRequestFromRow(row), nil
}

func (s *Service) Cancel(ctx context.Context, id uuid.UUID) error {
	ct, err := s.q.CancelPurgeRequest(ctx, id)
	if err != nil {
		return err
	}
	if ct == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Request, error) {
	rows, err := s.q.ListPurgeRequests(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Request, 0, len(rows))
	for _, r := range rows {
		out = append(out, *purgeRequestFromRow(r))
	}
	return out, nil
}

// purgeRequestFromRow maps a generated UserPurgeRequest model to the domain
// Request type. The helper lives here to keep mapping logic co-located with
// the repository code.
func purgeRequestFromRow(r dbgen.UserPurgeRequest) *Request {
	return &Request{
		ID:          r.ID,
		TenantID:    r.TenantID,
		UserID:      r.UserID,
		RequestedBy: toUUIDPtr(r.RequestedBy),
		Reason:      r.Reason,
		Status:      r.Status,
		GraceUntil:  r.GraceUntil,
		CompletedAt: toTimePtr(r.CompletedAt),
		CreatedAt:   r.CreatedAt,
	}
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
	batch, err := s.q.GetPendingPurgeRequests(ctx)
	if err != nil {
		return err
	}
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

	qTx := dbgen.New(tx)
	if err := qTx.PurgeUserPII(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeletePasswordCredentials(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeleteMFATOTP(ctx, userID); err != nil {
		return err
	}
	if err := qTx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return err
	}
	if err := qTx.RevokeUserSessions(ctx, userID); err != nil {
		return err
	}
	if err := qTx.CompletePurgeRequest(ctx, requestID); err != nil {
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
	row, err := s.q.InsertExportRequest(ctx, dbgen.InsertExportRequestParams{
		TenantID:    in.TenantID,
		UserID:      in.UserID,
		RequestedBy: pgUUIDNullable(in.By),
	})
	if err != nil {
		return nil, err
	}
	return &ExportRequest{
		ID:          row.ID,
		TenantID:    row.TenantID,
		UserID:      row.UserID,
		RequestedBy: toUUIDPtr(row.RequestedBy),
		Status:      row.Status,
		CompletedAt: toTimePtr(row.CompletedAt),
		CreatedAt:   row.CreatedAt,
	}, nil
}

// ListExports returns a tenant's export requests, most recent first.
func (s *Service) ListExports(ctx context.Context, tenantID uuid.UUID) ([]ExportRequest, error) {
	rows, err := s.q.ListExportRequests(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]ExportRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, ExportRequest{
			ID:          r.ID,
			TenantID:    r.TenantID,
			UserID:      r.UserID,
			RequestedBy: toUUIDPtr(r.RequestedBy),
			Status:      r.Status,
			Error:       r.Error,
			CompletedAt: toTimePtr(r.CompletedAt),
			CreatedAt:   r.CreatedAt,
		})
	}
	return out, nil
}

// GetExport fetches one export request, including its payload once ready.
func (s *Service) GetExport(ctx context.Context, tenantID, id uuid.UUID) (*ExportRequest, error) {
	r, err := s.q.GetExportRequest(ctx, dbgen.GetExportRequestParams{
		ID:       id,
		TenantID: tenantID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &ExportRequest{
		ID:          r.ID,
		TenantID:    r.TenantID,
		UserID:      r.UserID,
		RequestedBy: toUUIDPtr(r.RequestedBy),
		Status:      r.Status,
		Error:       r.Error,
		CompletedAt: toTimePtr(r.CompletedAt),
		CreatedAt:   r.CreatedAt,
	}
	if len(r.Payload) > 0 {
		if err := json.Unmarshal(r.Payload, &out.Payload); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// exportSweepTick picks pending export requests and builds their payload.
// Runs on the same ticker cadence as the purge sweep (see Run).
func (s *Service) exportSweepTick(ctx context.Context) error {
	batch, err := s.q.GetPendingExportRequests(ctx)
	if err != nil {
		return err
	}
	for _, e := range batch {
		if err := s.buildExport(ctx, e.ID, e.TenantID, e.UserID); err != nil {
			slog.Warn("gdpr export", "user", e.UserID, "err", err)
			msg := err.Error()
			_ = s.q.FailExportRequest(ctx, dbgen.FailExportRequestParams{
				ErrorMsg: &msg,
				ID:       e.ID,
			})
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
	return s.q.ReadyExportRequest(ctx, dbgen.ReadyExportRequestParams{
		Payload: raw,
		ID:      requestID,
	})
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
	// user.users.tenant_id is nullable → pgtype.UUID param.
	profileRow, err := s.q.GetUserProfileForExport(ctx, dbgen.GetUserProfileForExportParams{
		UserID:   userID,
		TenantID: pgUUIDNullable(&tenantID),
	})
	if err != nil {
		return nil, err
	}
	profile := exportProfile{
		Email:           profileRow.Email,
		Phone:           profileRow.Phone,
		DisplayName:     profileRow.DisplayName,
		Status:          profileRow.Status,
		EmailVerifiedAt: toTimePtr(profileRow.EmailVerifiedAt),
		PhoneVerifiedAt: toTimePtr(profileRow.PhoneVerifiedAt),
		CreatedAt:       profileRow.CreatedAt,
	}

	// auth.sessions.tenant_id is nullable (migration 0026) → pgtype.UUID param.
	sessRows, err := s.q.ListUserSessionsForExport(ctx, dbgen.ListUserSessionsForExportParams{
		UserID:   userID,
		TenantID: pgUUIDNullable(&tenantID),
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]exportSession, 0, len(sessRows))
	for _, r := range sessRows {
		// ip is COALESCE(host(ip), '') → interface{}; nil *string when empty.
		var ipPtr *string
		if ip, ok := r.Ip.(string); ok && ip != "" {
			ipPtr = &ip
		}
		sessions = append(sessions, exportSession{
			ID:         r.ID,
			IP:         ipPtr,
			UserAgent:  r.UserAgent,
			CreatedAt:  r.CreatedAt,
			LastSeenAt: r.LastSeenAt,
			RevokedAt:  toTimePtr(r.RevokedAt),
		})
	}

	pkRows, err := s.q.ListUserPasskeysForExport(ctx, userID)
	if err != nil {
		return nil, err
	}
	passkeys := make([]exportPasskey, 0, len(pkRows))
	for _, r := range pkRows {
		passkeys = append(passkeys, exportPasskey{
			ID:         r.ID,
			Name:       r.Name,
			Transports: r.Transports,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: toTimePtr(r.LastUsedAt),
		})
	}

	roleRows, err := s.q.ListUserRolesForExport(ctx, dbgen.ListUserRolesForExportParams{
		UserID:   userID,
		TenantID: tenantID,
	})
	if err != nil {
		return nil, err
	}
	roles := make([]exportRole, 0, len(roleRows))
	for _, r := range roleRows {
		roles = append(roles, exportRole{RoleName: r.RoleName, GrantedAt: r.GrantedAt})
	}

	// GetUserMFAStatus returns ErrNoRows when the user has no TOTP row — that
	// means mfaEnabled is false (the zero value), which is correct.
	mfaEnabled, err := s.q.GetUserMFAStatus(ctx, userID)
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
