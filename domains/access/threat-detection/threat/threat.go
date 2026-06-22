// Package threat records and surfaces security anomalies (the admin
// "Threats → Anomalies" screen). Detections write append-only rows into
// auth.security_events; the admin reads, summarises, and resolves them.
//
// The store is deliberately detection-agnostic: type/severity/status are open
// strings so new signals (new_device, geo anomalies, bot verdicts) plug in
// without schema or API changes. The first wired detection is brute-force /
// credential-stuffing, recorded when an account crosses the lockout threshold.
package threat

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

// Notifier sends an in-app notification to a user. Satisfied by
// *notification.Service; kept as an interface so threat doesn't import that
// package. nil = no notifications. Wired via SetNotifier.
type Notifier interface {
	Notify(ctx context.Context, tenantID, userID uuid.UUID, kind, title, description, href string) error
}

type Service struct {
	pool     *pgxpool.Pool
	notifier Notifier
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// SetNotifier wires the in-app notifier so security events can also alert the
// affected user. Called from cmd/server/main.go.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// Event is a detection's input. TenantID is required; UserID/IP/UserAgent are
// optional context. Status defaults to "open" and Severity to "low" when empty.
type Event struct {
	TenantID  uuid.UUID
	UserID    *uuid.UUID
	Type      string
	Severity  string
	Detail    string
	Status    string
	IP        string
	UserAgent string
}

// Anomaly is the read projection returned to the admin screen.
type Anomaly struct {
	ID         uuid.UUID  `json:"id"`
	Type       string     `json:"type"`
	Severity   string     `json:"severity"`
	Detail     string     `json:"detail"`
	Status     string     `json:"status"`
	UserID     *uuid.UUID `json:"user_id,omitempty"`
	UserEmail  *string    `json:"user_email,omitempty"`
	IP         *string    `json:"ip,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// Summary feeds the four KPI cards above the anomaly table.
type Summary struct {
	Open             int `json:"open"`
	Resolved24h      int `json:"resolved_24h"`
	AffectedAccounts int `json:"affected_accounts"`
	HighSeverity24h  int `json:"high_severity_24h"`
}

// Record appends a security event. Best-effort callers (detection hooks) should
// log and swallow the error so a detection write never breaks the auth path.
func (s *Service) Record(ctx context.Context, e Event) error {
	if e.Severity == "" {
		e.Severity = "low"
	}
	if e.Status == "" {
		e.Status = "open"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth.security_events (tenant_id, user_id, type, severity, detail, status, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7,'')::inet, NULLIF($8,''))
	`, e.TenantID, e.UserID, e.Type, e.Severity, e.Detail, e.Status, e.IP, e.UserAgent)
	return err
}

// OnAccountLocked implements the auth package's AnomalyRecorder: it is called
// when an account crosses the failed-login lockout threshold. It resolves the
// offending email to a tenant + user and records a credential-stuffing anomaly.
// Best-effort throughout — an unknown email (probing) has no tenant to scope to
// and is simply skipped; storage errors are logged, not surfaced.
func (s *Service) OnAccountLocked(ctx context.Context, email string) {
	var userID, tenantID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id FROM "user".users
		WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL AND tenant_id IS NOT NULL
		LIMIT 1
	`, email).Scan(&userID, &tenantID)
	if err != nil {
		// No matching tenant user (unknown email or tenant-less) — nothing to
		// scope a tenant incident to.
		return
	}
	if rerr := s.Record(ctx, Event{
		TenantID: tenantID,
		UserID:   &userID,
		Type:     "credential_stuffing",
		Severity: "high",
		Status:   "rate-limited",
		Detail:   "Account temporarily locked after repeated failed sign-in attempts.",
	}); rerr != nil {
		slog.Warn("record credential_stuffing anomaly", "err", rerr)
	}
	// Also alert the affected user in-app — a "was this you?" security nudge.
	if s.notifier != nil {
		if nerr := s.notifier.Notify(ctx, tenantID, userID, "alert",
			"Unusual sign-in activity",
			"Your account was temporarily locked after several failed sign-in attempts. If this wasn't you, reset your password.",
			"/account/security"); nerr != nil {
			slog.Warn("notify account locked", "err", nerr)
		}
	}
}

// List returns the most recent anomalies for a tenant, newest first.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]Anomaly, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.type, e.severity, e.detail, e.status, e.user_id, u.email,
		       host(e.ip), e.created_at, e.resolved_at
		FROM auth.security_events e
		LEFT JOIN "user".users u ON u.id = e.user_id
		WHERE e.tenant_id = $1
		ORDER BY e.created_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Anomaly, 0)
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &a.Detail, &a.Status,
			&a.UserID, &a.UserEmail, &a.IP, &a.CreatedAt, &a.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Summary computes the KPI counts for a tenant in a single pass.
func (s *Service) Summary(ctx context.Context, tenantID uuid.UUID) (*Summary, error) {
	var sm Summary
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'open'),
			COUNT(*) FILTER (WHERE resolved_at >= NOW() - INTERVAL '24 hours'),
			COUNT(DISTINCT user_id) FILTER (WHERE status = 'open' AND user_id IS NOT NULL),
			COUNT(*) FILTER (WHERE severity = 'high' AND created_at >= NOW() - INTERVAL '24 hours')
		FROM auth.security_events
		WHERE tenant_id = $1
	`, tenantID).Scan(&sm.Open, &sm.Resolved24h, &sm.AffectedAccounts, &sm.HighSeverity24h)
	if err != nil {
		return nil, err
	}
	return &sm, nil
}

// Resolve marks an open anomaly resolved. Tenant-scoped so an admin can never
// resolve another tenant's incident.
func (s *Service) Resolve(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE auth.security_events
		SET status = 'resolved', resolved_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND resolved_at IS NULL
	`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/security/anomalies", h.list)
	r.Get("/tenants/{tenantID}/security/anomalies/summary", h.summary)
	r.Post("/tenants/{tenantID}/security/anomalies/{id}/resolve", h.resolve)
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

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID, 50)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sm, err := h.Service.Summary(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sm)
}

func (h *Handler) resolve(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Resolve(r.Context(), id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Anomaly resolved."})
}
