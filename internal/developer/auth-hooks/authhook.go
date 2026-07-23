// Package authhook implements synchronous Auth Actions/Hooks: after credentials
// verify, Run POSTs a signed event to a tenant's policy endpoint that returns
// allow/deny. Inert until a hook is enabled; on error/timeout fail_open decides
// (default allow, so a hook outage never locks everyone out).
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

	"github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q      *dbgen.Queries
	client *http.Client
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), client: &http.Client{Timeout: hookTimeout}}
}

// Run implements auth.LoginHook. It returns a non-nil (ErrForbidden) error to
// DENY the sign-in, or nil to allow — in which case the returned map (possibly
// nil) carries any custom claims the hook asked to be injected into the
// issued access token. A missing/disabled hook allows with no claims. Safe by
// construction: any path that can't reach a definite "deny" allows (subject to
// the hook's fail_open when the call itself fails).
func (s *Service) Run(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error) {
	if tenantID == uuid.Nil {
		return nil, nil
	}
	row, err := s.q.GetActiveHook(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return nil, nil // no hook (or can't load it) → never block login on infra
	}

	payload, _ := json.Marshal(map[string]any{
		"trigger":   "post_login",
		"tenant_id": tenantID,
		"user_id":   userID,
		"email":     email,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	body, callErr := s.call(ctx, row.Url, row.Secret, payload)
	msg, denied, claims := decide(row.FailOpen, callErr, body)
	if denied {
		return nil, errs.ErrForbidden.WithMessage(msg).WithDetail("blocked by auth hook")
	}
	return claims, nil
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
// decision, plus any custom claims the hook asked to inject on allow. Pure, so
// it's unit-tested. On a call error it honours fail_open; on success it denies
// only when the body explicitly says decision="deny", and otherwise carries
// through an optional "claims" object verbatim.
func decide(failOpen bool, callErr error, body []byte) (denyMsg string, denied bool, claims map[string]any) {
	if callErr != nil {
		if failOpen {
			return "", false, nil
		}
		return "Sign-in is temporarily unavailable. Please try again later.", true, nil
	}
	var r struct {
		Decision string         `json:"decision"`
		Message  string         `json:"message"`
		Claims   map[string]any `json:"claims"`
	}
	_ = json.Unmarshal(body, &r)
	if strings.EqualFold(strings.TrimSpace(r.Decision), "deny") {
		msg := strings.TrimSpace(r.Message)
		if msg == "" {
			msg = "Sign-in was blocked by your organization's policy."
		}
		return msg, true, nil
	}
	return "", false, r.Claims
}

func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, url, secret string, failOpen bool) (*Hook, error) {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return nil, errs.ErrUnprocessable.WithDetail("url must be an absolute http(s) URL")
	}
	row, err := s.q.CreateHook(ctx, dbgen.CreateHookParams{
		TenantID: tenantID,
		Url:      url,
		Secret:   secret,
		FailOpen: failOpen,
	})
	if err != nil {
		return nil, err
	}
	return &Hook{
		ID:        row.ID,
		Trigger:   row.Trigger,
		URL:       row.Url,
		Enabled:   row.Enabled,
		FailOpen:  row.FailOpen,
		CreatedAt: row.CreatedAt,
	}, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Hook, error) {
	rows, err := s.q.ListHooks(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Hook, 0, len(rows))
	for _, row := range rows {
		out = append(out, Hook{
			ID:        row.ID,
			Trigger:   row.Trigger,
			URL:       row.Url,
			Enabled:   row.Enabled,
			FailOpen:  row.FailOpen,
			CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) Update(ctx context.Context, id, tenantID uuid.UUID, enabled, failOpen bool) error {
	n, err := s.q.UpdateHook(ctx, dbgen.UpdateHookParams{
		Enabled:  enabled,
		FailOpen: failOpen,
		ID:       id,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	n, err := s.q.DeleteHook(ctx, dbgen.DeleteHookParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

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
