// Package authhook implements synchronous Auth Actions/Hooks: a tenant plugs a
// policy endpoint into the login flow. After credentials verify, Run POSTs a
// signed event to the hook URL; the hook returns allow/deny. It is inert until
// a tenant configures an enabled hook, and is bounded by a short timeout. When
// the hook errors or times out, fail_open decides the outcome (default: allow,
// so a hook outage never locks everyone out; strict tenants can set fail-closed).
package authhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

const hookTimeout = 3 * time.Second

type Hook struct {
	ID        uuid.UUID `json:"id"`
	Trigger   string    `json:"trigger"`
	URL       string    `json:"url"`
	Enabled   bool      `json:"enabled"`
	FailOpen  bool      `json:"fail_open"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct {
	pool   *pgxpool.Pool
	client *http.Client
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, client: &http.Client{Timeout: hookTimeout}}
}

// Run implements auth.LoginHook. It returns a non-nil (ErrForbidden) error to
// DENY the sign-in, or nil to allow. A missing/disabled hook allows. Safe by
// construction: any path that can't reach a definite "deny" allows (subject to
// the hook's fail_open when the call itself fails).
func (s *Service) Run(ctx context.Context, tenantID, userID uuid.UUID, email string) error {
	if tenantID == uuid.Nil {
		return nil
	}
	var url, secret string
	var failOpen bool
	err := s.pool.QueryRow(ctx, `
		SELECT url, secret, fail_open FROM tenant.auth_hooks
		WHERE tenant_id = $1 AND enabled AND trigger = 'post_login'
		ORDER BY created_at LIMIT 1
	`, tenantID).Scan(&url, &secret, &failOpen)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return nil // no hook (or can't load it) → never block login on infra
	}

	payload, _ := json.Marshal(map[string]any{
		"trigger":   "post_login",
		"tenant_id": tenantID,
		"user_id":   userID,
		"email":     email,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	body, callErr := s.call(ctx, url, secret, payload)
	msg, denied := decide(failOpen, callErr, body)
	if denied {
		return errs.ErrForbidden.WithMessage(msg).WithDetail("blocked by auth hook")
	}
	return nil
}

// call POSTs the signed payload, returning the response body and a non-nil
// error on transport failure, timeout, or a non-2xx status.
func (s *Service) call(ctx context.Context, url, secret string, payload []byte) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Qeet-Signature", "sha256="+sign(secret, payload))
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return b, errors.New("hook returned non-2xx")
	}
	return b, nil
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// decide turns a hook call's outcome into an allow (denied=false) or deny
// decision. Pure, so it's unit-tested. On a call error it honours fail_open;
// on success it denies only when the body explicitly says decision="deny".
func decide(failOpen bool, callErr error, body []byte) (denyMsg string, denied bool) {
	if callErr != nil {
		if failOpen {
			return "", false
		}
		return "Sign-in is temporarily unavailable. Please try again later.", true
	}
	var r struct {
		Decision string `json:"decision"`
		Message  string `json:"message"`
	}
	_ = json.Unmarshal(body, &r)
	if strings.EqualFold(strings.TrimSpace(r.Decision), "deny") {
		msg := strings.TrimSpace(r.Message)
		if msg == "" {
			msg = "Sign-in was blocked by your organization's policy."
		}
		return msg, true
	}
	return "", false
}

// --- CRUD ---

func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, url, secret string, failOpen bool) (*Hook, error) {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return nil, errs.ErrUnprocessable.WithDetail("url must be an absolute http(s) URL")
	}
	var h Hook
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.auth_hooks (tenant_id, url, secret, fail_open)
		VALUES ($1, $2, $3, $4)
		RETURNING id, trigger, url, enabled, fail_open, created_at
	`, tenantID, url, secret, failOpen).Scan(&h.ID, &h.Trigger, &h.URL, &h.Enabled, &h.FailOpen, &h.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Hook, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, trigger, url, enabled, fail_open, created_at
		FROM tenant.auth_hooks WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Hook, 0)
	for rows.Next() {
		var h Hook
		if err := rows.Scan(&h.ID, &h.Trigger, &h.URL, &h.Enabled, &h.FailOpen, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Service) Update(ctx context.Context, id, tenantID uuid.UUID, enabled, failOpen bool) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenant.auth_hooks SET enabled = $3, fail_open = $4 WHERE id = $1 AND tenant_id = $2
	`, id, tenantID, enabled, failOpen)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM tenant.auth_hooks WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// --- handlers ---

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/auth-hooks", h.list)
	r.Post("/tenants/{tenantID}/auth-hooks", h.create)
	r.Patch("/tenants/{tenantID}/auth-hooks/{id}", h.patch)
	r.Delete("/tenants/{tenantID}/auth-hooks/{id}", h.del)
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
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		URL      string `json:"url"`
		Secret   string `json:"secret"`
		FailOpen *bool  `json:"fail_open"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	failOpen := true
	if in.FailOpen != nil {
		failOpen = *in.FailOpen
	}
	hook, err := h.Service.Create(r.Context(), tenantID, in.URL, in.Secret, failOpen)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, hook)
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
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
	var in struct {
		Enabled  bool `json:"enabled"`
		FailOpen bool `json:"fail_open"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Update(r.Context(), id, tenantID, in.Enabled, in.FailOpen); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": in.Enabled, "fail_open": in.FailOpen})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
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
	if err := h.Service.Delete(r.Context(), id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
