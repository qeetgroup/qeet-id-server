// Package webhook lets tenants subscribe to domain events and receive a
// signed POST. Deliveries are persisted before send so retries survive
// process restarts; a background dispatcher walks the queue.
package webhook

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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Subscription struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	URL        string     `json:"url"`
	Events     []string   `json:"events"`
	DisabledAt *time.Time `json:"disabled_at"`
	CreatedAt  time.Time  `json:"created_at"`
	// Secret is returned only on create.
	Secret string `json:"secret,omitempty"`
}

type Service struct {
	pool   *pgxpool.Pool
	client *http.Client
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{
		pool:   pool,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

type CreateInput struct {
	TenantID uuid.UUID `json:"tenant_id"`
	URL      string    `json:"url"`
	Events   []string  `json:"events"`
}

func (s *Service) Create(ctx context.Context, tx pgx.Tx, in CreateInput) (*Subscription, error) {
	secret, _, err := codes.URLToken()
	if err != nil {
		return nil, err
	}
	var sub Subscription
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant.webhook_subscriptions (tenant_id, url, secret, events)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, url, events, disabled_at, created_at
	`, in.TenantID, in.URL, secret, in.Events).Scan(&sub.ID, &sub.TenantID, &sub.URL, &sub.Events, &sub.DisabledAt, &sub.CreatedAt)
	if err != nil {
		return nil, err
	}
	sub.Secret = secret
	return &sub, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Subscription, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, url, events, disabled_at, created_at
		FROM tenant.webhook_subscriptions
		WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.ID, &sub.TenantID, &sub.URL, &sub.Events, &sub.DisabledAt, &sub.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Subscription, error) {
	var sub Subscription
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, url, events, disabled_at, created_at
		FROM tenant.webhook_subscriptions WHERE id = $1
	`, id).Scan(&sub.ID, &sub.TenantID, &sub.URL, &sub.Events, &sub.DisabledAt, &sub.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sub, nil
}

// Disable marks the subscription disabled and returns the (tenantID, url)
// so the caller doesn't have to re-query for the audit row.
func (s *Service) Disable(ctx context.Context, tx pgx.Tx, id uuid.UUID) (uuid.UUID, string, error) {
	var tenantID uuid.UUID
	var url string
	err := tx.QueryRow(ctx, `
		UPDATE tenant.webhook_subscriptions SET disabled_at = NOW()
		WHERE id = $1 AND disabled_at IS NULL
		RETURNING tenant_id, url
	`, id).Scan(&tenantID, &url)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return tenantID, url, nil
}

// Enqueue persists a delivery for every matching subscription.
func (s *Service) Enqueue(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM tenant.webhook_subscriptions
		WHERE tenant_id = $1 AND disabled_at IS NULL
		  AND ($2 = ANY(events) OR events = '{}'::text[])
	`, tenantID, eventType)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO tenant.webhook_deliveries (subscription_id, event_type, payload, next_attempt_at)
			VALUES ($1, $2, $3, NOW())
		`, id, eventType, body)
		if err != nil {
			return err
		}
	}
	return nil
}

// RunDispatcher loops, picking due deliveries and posting them with an
// HMAC signature header. Exponential-ish retry: doubles next_attempt_at
// up to ~1 hour.
func (s *Service) RunDispatcher(ctx context.Context) {
	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if err := s.tick(ctx); err != nil {
				slog.Warn("webhook tick", "err", err)
			}
		}
	}
}

func (s *Service) tick(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.subscription_id, d.event_type, d.payload, d.attempt, sub.url, sub.secret
		FROM tenant.webhook_deliveries d
		JOIN tenant.webhook_subscriptions sub ON sub.id = d.subscription_id
		WHERE d.delivered_at IS NULL
		  AND d.next_attempt_at <= NOW()
		  AND sub.disabled_at IS NULL
		ORDER BY d.created_at
		LIMIT 20
		FOR UPDATE SKIP LOCKED
	`)
	if err != nil {
		return err
	}
	type item struct {
		ID, SubID uuid.UUID
		Event     string
		Payload   []byte
		Attempt   int
		URL       string
		Secret    string
	}
	var batch []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.SubID, &it.Event, &it.Payload, &it.Attempt, &it.URL, &it.Secret); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, it)
	}
	rows.Close()
	for _, it := range batch {
		status, respBody, derr := s.deliver(ctx, it.URL, it.Secret, it.Event, it.Payload)
		now := time.Now()
		if derr == nil && status >= 200 && status < 300 {
			_, _ = s.pool.Exec(ctx, `
				UPDATE tenant.webhook_deliveries
				SET delivered_at = NOW(), status_code = $1, response_body = $2, attempt = attempt + 1, error = NULL
				WHERE id = $3
			`, status, truncate(respBody, 4000), it.ID)
			continue
		}
		backoff := time.Duration(1<<min(it.Attempt, 8)) * 30 * time.Second
		if backoff > time.Hour {
			backoff = time.Hour
		}
		errStr := ""
		if derr != nil {
			errStr = derr.Error()
		}
		_, _ = s.pool.Exec(ctx, `
			UPDATE tenant.webhook_deliveries
			SET attempt = attempt + 1,
			    status_code = $1,
			    response_body = $2,
			    error = $3,
			    next_attempt_at = $4
			WHERE id = $5
		`, status, truncate(respBody, 4000), errStr, now.Add(backoff), it.ID)
	}
	return nil
}

func (s *Service) deliver(ctx context.Context, url, secret, eventType string, body []byte) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Qeet-Event", eventType)
	req.Header.Set("X-Qeet-Signature", "sha256="+sign(secret, body))
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, string(rb), errors.New("non-2xx response")
	}
	return resp.StatusCode, string(rb), nil
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/webhooks", h.create)
	r.Get("/tenants/{tenantID}/webhooks", h.list)
	r.Delete("/webhooks/{id}", h.disable)
	r.Post("/webhooks/{id}/test", h.test)
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

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.URL == "" || in.TenantID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("tenant_id and url required"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	sub, err := h.Service.Create(ctx, tx, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := sub.TenantID
	rid := sub.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "webhook.subscription_created",
		ResourceType: "webhook_subscription",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"url": sub.URL, "events": sub.Events},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, sub)
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

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	tenantID, url, err := h.Service.Disable(ctx, tx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	rid := id
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "webhook.subscription_disabled",
		ResourceType: "webhook_subscription",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"url": url},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	sub, err := h.Service.Get(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Enqueue(r.Context(), sub.TenantID, "test.ping", map[string]any{
		"hello": "world",
		"at":    time.Now().UTC(),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"queued": true, "subscription": sub.ID})
}

// EventBus is satisfied by webhook.Service so other modules can publish
// without depending on the concrete type.
type EventBus interface {
	Enqueue(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error
}

// ErrBadRequest is re-exported for callers that don't want the platform
// dependency. Kept here intentionally to keep webhook a self-contained
// API boundary.
var _ EventBus = (*Service)(nil)

