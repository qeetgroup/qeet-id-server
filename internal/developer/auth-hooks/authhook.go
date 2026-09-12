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
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
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
	egress *egress.Policy
	box    *envelope.Cipher
}

func NewService(pool *pgxpool.Pool, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{pool: pool, q: dbgen.New(pool), client: policy.HTTPClient(hookTimeout), egress: policy}
}

func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// Run implements auth.LoginHook. It returns a non-nil (ErrAuthHookDenied) error to
// DENY the sign-in, or nil to allow — in which case the returned map (possibly
// nil) carries any custom claims the hook asked to be injected into the
// issued access token. A missing/disabled hook allows with no claims. Safe by
// construction: any path that can't reach a definite "deny" allows (subject to
// the hook's fail_open when the call itself fails).
func (s *Service) Run(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error) {
	if tenantID == uuid.Nil {
		return nil, nil
	}
	var hookID uuid.UUID
	var url, legacySecret string
	var ciphertext, nonce []byte
	var failOpen bool
	err := s.pool.QueryRow(ctx, `
		SELECT id, url, secret, secret_ct, secret_nonce, fail_open
		FROM tenant.auth_hooks
		WHERE tenant_id = $1 AND enabled AND trigger = 'post_login'
		ORDER BY created_at LIMIT 1
	`, tenantID).Scan(&hookID, &url, &legacySecret, &ciphertext, &nonce, &failOpen)
	if errors.Is(err, pgx.ErrNoRows) || err != nil {
		return nil, nil // no hook (or can't load it) → never block login on infra
	}
	secretValue := legacySecret
	if len(ciphertext) > 0 {
		if s.box == nil {
			return nil, nil
		}
		plain, openErr := s.box.Open(tenantID, "auth-hook-signing", hookID.String(), ciphertext, nonce)
		if openErr != nil {
			return nil, nil
		}
		secretValue = string(plain)
	} else if legacySecret != "" && s.box != nil {
		ct, newNonce, sealErr := s.box.Seal(tenantID, "auth-hook-signing", hookID.String(), []byte(legacySecret))
		if sealErr == nil {
			_, _ = s.pool.Exec(ctx, `
				UPDATE tenant.auth_hooks
				SET secret = '', secret_ct = $2, secret_nonce = $3, encryption_version = 1
				WHERE id = $1 AND secret_ct IS NULL
			`, hookID, ct, newNonce)
		}
	}

	payload, _ := json.Marshal(map[string]any{
		"trigger":   "post_login",
		"tenant_id": tenantID,
		"user_id":   userID,
		"email":     email,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	body, callErr := s.call(ctx, url, secretValue, payload)
	msg, denied, claims := decide(failOpen, callErr, body)
	if denied {
		return nil, errs.ErrAuthHookDenied.WithMessage(msg)
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
//
// An UNPARSEABLE body is treated as a call failure, not as an allow. Fail-open
// by default is a deliberate product decision (there is an ADR for it), but that
// decision is about what happens when the hook cannot be reached — it is not a
// licence to ignore a tenant that has explicitly set fail_open=false. A hook
// answering 2xx with a truncated, empty or non-JSON body has told us nothing,
// and swallowing the unmarshal error meant `decision` stayed "" and the sign-in
// was ALLOWED even for a fail-closed tenant. Routing it through the same
// failOpen branch keeps the documented default intact while making the opt-out
// actually enforceable.
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
	if err := json.Unmarshal(body, &r); err != nil {
		if failOpen {
			return "", false, nil
		}
		return "Sign-in is temporarily unavailable. Please try again later.", true, nil
	}
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
	return s.CreateWithActor(ctx, tenantID, url, secret, failOpen, audit.Actor{Type: "system"})
}

func (s *Service) CreateWithActor(ctx context.Context, tenantID uuid.UUID, url, secret string, failOpen bool, actor audit.Actor) (*Hook, error) {
	if _, err := s.egress.ValidateHTTPURL(url); err != nil {
		return nil, errs.ErrAuthHookURLInvalid
	}
	if s.box == nil {
		return nil, errs.ErrInternalServer.WithDetail("auth-hook secret encryption is unavailable")
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(tenantID, "auth-hook-signing", id.String(), []byte(secret))
	if err != nil {
		return nil, err
	}
	var row struct {
		ID        uuid.UUID
		Trigger   string
		URL       string
		Enabled   bool
		FailOpen  bool
		CreatedAt time.Time
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant.auth_hooks
		    (id, tenant_id, url, secret, secret_ct, secret_nonce, encryption_version, fail_open)
		VALUES ($1, $2, $3, '', $4, $5, 1, $6)
		RETURNING id, trigger, url, enabled, fail_open, created_at
	`, id, tenantID, url, ciphertext, nonce, failOpen).Scan(
		&row.ID, &row.Trigger, &row.URL, &row.Enabled, &row.FailOpen, &row.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	hook := &Hook{
		ID:        row.ID,
		Trigger:   row.Trigger,
		URL:       row.URL,
		Enabled:   row.Enabled,
		FailOpen:  row.FailOpen,
		CreatedAt: row.CreatedAt,
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "auth_hook.created", "auth_hook", hook.ID,
		map[string]any{"url": hook.URL, "fail_open": hook.FailOpen})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: hook.ID, Topic: "auth-hook.events", EventType: "auth_hook.created",
		Payload: map[string]any{"hook_id": hook.ID, "tenant_id": tenantID, "url": hook.URL, "fail_open": hook.FailOpen},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return hook, nil
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
	return s.UpdateWithActor(ctx, id, tenantID, enabled, failOpen, audit.Actor{Type: "system"})
}

func (s *Service) UpdateWithActor(ctx context.Context, id, tenantID uuid.UUID, enabled, failOpen bool, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).UpdateHook(ctx, dbgen.UpdateHookParams{
		Enabled:  enabled,
		FailOpen: failOpen,
		ID:       id,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrAuthHookNotFound
	}
	metadata := map[string]any{"enabled": enabled, "fail_open": failOpen}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "auth_hook.updated", "auth_hook", id, metadata)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "auth-hook.events", EventType: "auth_hook.updated", Payload: metadata}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.DeleteWithActor(ctx, id, tenantID, audit.Actor{Type: "system"})
}

func (s *Service) DeleteWithActor(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteHook(ctx, dbgen.DeleteHookParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrAuthHookNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "auth_hook.deleted", "auth_hook", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "auth-hook.events", EventType: "auth_hook.deleted", Payload: map[string]any{"hook_id": id, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type Handler struct {
	Service *Service
}

func actorOf(r *http.Request) audit.Actor {
	actor := audit.Actor{Type: "system", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if principal := httpx.PrincipalFromCtx(r.Context()); principal != nil {
		actor.UserID = principal.UserID
		if principal.ActorType != "" {
			actor.Type = principal.ActorType
		}
	}
	return actor
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
		return uuid.Nil, errs.ErrAuthHookInvalidID
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrAuthHookTenantMismatch
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
	hook, err := h.Service.CreateWithActor(r.Context(), tenantID, in.URL, in.Secret, failOpen, actorOf(r))
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
		httpx.WriteError(w, r, errs.ErrAuthHookInvalidID)
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
	if err := h.Service.UpdateWithActor(r.Context(), id, tenantID, in.Enabled, in.FailOpen, actorOf(r)); err != nil {
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
		httpx.WriteError(w, r, errs.ErrAuthHookInvalidID)
		return
	}
	if err := h.Service.DeleteWithActor(r.Context(), id, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
