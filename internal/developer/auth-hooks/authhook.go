// Package authhook runs an organisation's synchronous sign-in hook: after the
// credentials check, Run POSTs a signed event to the hook's URL, which answers
// allow or deny. When the hook gives no answer, fail_open decides (allow by
// default, so an outage never locks everyone out) and the skip is recorded.
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
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const hookTimeout = 3 * time.Second

// hookUnavailable is what a sign-in is told when a fail-closed hook gave no
// answer.
const hookUnavailable = "Sign-in is temporarily unavailable. Please try again later."

// Why a hook gave no answer.
const (
	skipUnreadable        = "unreadable"         // the hook couldn't be read
	skipSecretUnavailable = "secret_unavailable" // its signing secret couldn't be opened
	skipCallFailed        = "call_failed"        // the call errored, timed out or wasn't 2xx
	skipUnparseable       = "unparseable"        // the answer couldn't be read
)

var hookSkips = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "auth_hook_skipped_total",
	Help: "Sign-in hook evaluations that got no answer from the hook, by reason (unreadable, secret_unavailable, call_failed, unparseable) and outcome (allowed where the hook fails open, refused where it fails closed).",
}, []string{"reason", "outcome"})

func init() {
	// Publish every series at zero so an alert can rate() it from the start.
	for _, reason := range []string{skipUnreadable, skipSecretUnavailable, skipCallFailed, skipUnparseable} {
		for _, outcome := range []string{"allowed", "refused"} {
			hookSkips.WithLabelValues(reason, outcome)
		}
	}
}

// hookState is an organisation's sign-in hook as last read: none, or one and
// whether it fails open.
type hookState struct {
	present  bool
	id       uuid.UUID
	failOpen bool
}

// Hook is a tenant's login hook, without its signing secret.
type Hook struct {
	ID        uuid.UUID `json:"id"`
	Trigger   string    `json:"trigger"`
	URL       string    `json:"url"`
	Enabled   bool      `json:"enabled"`
	FailOpen  bool      `json:"fail_open"`
	CreatedAt time.Time `json:"created_at"`
}

// Service manages and runs sign-in hooks. known holds each organisation's hook
// as last read (uuid.UUID → hookState), for a sign-in made while the hook can't
// be read.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	client *http.Client
	egress *egress.Policy
	box    *envelope.Cipher
	known  sync.Map
}

// NewService returns the login hook service.
func NewService(pool *pgxpool.Pool, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{pool: pool, q: dbgen.New(pool), client: policy.HTTPClient(hookTimeout), egress: policy}
}

// SetCipher sets the cipher that encrypts login hook secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// Run implements auth.LoginHook. It returns ErrAuthHookDenied to refuse the
// sign-in, or nil with any custom claims the hook asked to add to the access
// token. No enabled hook allows with no claims; a hook that gives no answer is
// handled by skipped.
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
	if errors.Is(err, pgx.ErrNoRows) {
		s.known.Store(tenantID, hookState{})
		return nil, nil
	}
	if err != nil {
		// Whether the organisation's hook fails open can't be read now, so it
		// is taken from the last time it was read here: a fail-closed
		// organisation stays fail-closed. Never read, the hook's default
		// (fail open) applies.
		last, _ := s.known.Load(tenantID)
		state, seen := last.(hookState)
		return s.skipped(ctx, tenantID, userID, state.id, skipUnreadable, !seen || !state.present || state.failOpen, err)
	}
	s.known.Store(tenantID, hookState{present: true, id: hookID, failOpen: failOpen})
	secretValue := legacySecret
	if len(ciphertext) > 0 {
		if s.box == nil {
			return s.skipped(ctx, tenantID, userID, hookID, skipSecretUnavailable, failOpen, errors.New("no cipher to open the signing secret"))
		}
		plain, openErr := s.box.Open(tenantID, "auth-hook-signing", hookID.String(), ciphertext, nonce)
		if openErr != nil {
			return s.skipped(ctx, tenantID, userID, hookID, skipSecretUnavailable, failOpen, openErr)
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
	if callErr != nil {
		return s.skipped(ctx, tenantID, userID, hookID, skipCallFailed, failOpen, callErr)
	}
	if _, ok := parseAnswer(body); !ok {
		return s.skipped(ctx, tenantID, userID, hookID, skipUnparseable, failOpen, errors.New("the hook's answer isn't a JSON object"))
	}
	msg, denied, claims := decide(failOpen, nil, body)
	if denied {
		return nil, errs.ErrAuthHookDenied.WithMessage(msg)
	}
	return claims, nil
}

// skipped answers a sign-in the hook gave no answer for, refusing it with
// hookUnavailable unless failOpen, and records the skip (an auth_hook.skipped
// audit event and the auth_hook_skipped_total metric) so an alert can fire.
func (s *Service) skipped(ctx context.Context, tenantID, userID, hookID uuid.UUID, reason string, failOpen bool, cause error) (map[string]any, error) {
	outcome := "allowed"
	if !failOpen {
		outcome = "refused"
	}
	hookSkips.WithLabelValues(reason, outcome).Inc()
	slog.Warn("authhook: the sign-in hook gave no answer", "tenant_id", tenantID, "hook_id", hookID, "reason", reason, "outcome", outcome, "err", cause)
	var resource *uuid.UUID
	if hookID != uuid.Nil {
		resource = &hookID
	}
	// Recorded even when the request is gone, within a short bound.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.record(rctx, audit.Event{
		TenantID: &tenantID, ActorUserID: &userID, ActorType: "user",
		Action: "auth_hook.skipped", ResourceType: "auth_hook", ResourceID: resource,
		Metadata: map[string]any{"reason": reason, "outcome": outcome, "fail_open": failOpen},
	}); err != nil {
		slog.Warn("authhook: record a skipped hook", "tenant_id", tenantID, "reason", reason, "err", err)
	}
	if !failOpen {
		return nil, errs.ErrAuthHookDenied.WithMessage(hookUnavailable)
	}
	return nil, nil
}

// record writes one audit event in its own transaction.
func (s *Service) record(ctx context.Context, e audit.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// answer is what a hook said.
type answer struct {
	Decision string         `json:"decision"`
	Message  string         `json:"message"`
	Claims   map[string]any `json:"claims"`
}

// parseAnswer reads a hook's answer; ok is false when it can't be read.
func parseAnswer(body []byte) (answer, bool) {
	var r answer
	if err := json.Unmarshal(body, &r); err != nil {
		return answer{}, false
	}
	return r, true
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

// decide turns a hook call's outcome into a deny message, or an allow with the
// hook's custom claims. It denies on decision "deny" and, unless failOpen, when
// the call failed or the body can't be parsed: a 2xx with an unreadable body
// has said nothing, so it must not get past a fail-closed hook.
func decide(failOpen bool, callErr error, body []byte) (denyMsg string, denied bool, claims map[string]any) {
	if callErr != nil {
		if failOpen {
			return "", false, nil
		}
		return hookUnavailable, true, nil
	}
	r, ok := parseAnswer(body)
	if !ok {
		if failOpen {
			return "", false, nil
		}
		return hookUnavailable, true, nil
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

// Create registers a login hook at url, its signing secret encrypted, recorded
// as actor's. The URL must be an allowed outbound destination.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, url, secret string, failOpen bool, actor audit.Actor) (*Hook, error) {
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

// List returns the tenant's hooks.
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

// Update enables or disables one of the tenant's hooks and sets whether it
// fails open, recorded as actor's.
func (s *Service) Update(ctx context.Context, id, tenantID uuid.UUID, enabled, failOpen bool, actor audit.Actor) error {
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

// Delete removes one of the tenant's hooks, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
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

// Handler serves the login hook HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the login hook routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/auth-hooks", h.list)
	r.Post("/tenants/{tenantID}/auth-hooks", h.create)
	r.Patch("/tenants/{tenantID}/auth-hooks/{id}", h.patch)
	r.Delete("/tenants/{tenantID}/auth-hooks/{id}", h.del)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrAuthHookInvalidID, errs.ErrAuthHookTenantMismatch)
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
	hook, err := h.Service.Create(r.Context(), tenantID, in.URL, in.Secret, failOpen, audit.ActorOf(r))
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
	if err := h.Service.Update(r.Context(), id, tenantID, in.Enabled, in.FailOpen, audit.ActorOf(r)); err != nil {
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
	if err := h.Service.Delete(r.Context(), id, tenantID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
