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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhooks/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q      *dbgen.Queries
	client *http.Client
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{
		pool:   pool,
		q:      dbgen.New(pool),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// tsPtr converts a pgtype.Timestamptz to *time.Time (nil when not valid).
func tsPtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

// int32Ptr converts an int to *int32 for sqlc status-code params (nil when 0).
func int32Ptr(v int) *int32 {
	if v == 0 {
		return nil
	}
	i := int32(v)
	return &i
}

// strPtr returns nil for an empty string, &s otherwise (used for optional
// error/body fields in delivery update params).
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// toTS converts a time.Time to a valid pgtype.Timestamptz.
func toTS(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

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
	row, err := s.q.WithTx(tx).CreateWebhookSubscription(ctx, dbgen.CreateWebhookSubscriptionParams{
		TenantID: in.TenantID,
		Url:      in.URL,
		Secret:   secret,
		Events:   in.Events,
	})
	if err != nil {
		return nil, err
	}
	return &Subscription{
		ID: row.ID, TenantID: row.TenantID, URL: row.Url,
		Events: row.Events, DisabledAt: tsPtr(row.DisabledAt), CreatedAt: row.CreatedAt,
		Secret: secret,
	}, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Subscription, error) {
	rows, err := s.q.ListWebhookSubscriptions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Subscription, 0, len(rows))
	for _, row := range rows {
		out = append(out, Subscription{
			ID: row.ID, TenantID: row.TenantID, URL: row.Url,
			Events: row.Events, DisabledAt: tsPtr(row.DisabledAt), CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Subscription, error) {
	row, err := s.q.GetWebhookSubscription(ctx, dbgen.GetWebhookSubscriptionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Subscription{
		ID: row.ID, TenantID: row.TenantID, URL: row.Url,
		Events: row.Events, DisabledAt: tsPtr(row.DisabledAt), CreatedAt: row.CreatedAt,
	}, nil
}

// Disable marks the subscription disabled and returns the (tenantID, url)
// so the caller doesn't have to re-query for the audit row.
func (s *Service) Disable(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) (uuid.UUID, string, error) {
	row, err := s.q.WithTx(tx).DisableWebhookSubscription(ctx, dbgen.DisableWebhookSubscriptionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return row.TenantID, row.Url, nil
}

// Delivery is one attempt-tracked dispatch of an event to a subscription,
// projected for the admin delivery viewer (payload + response for debugging).
type Delivery struct {
	ID            uuid.UUID  `json:"id"`
	EventType     string     `json:"event_type"`
	Attempt       int        `json:"attempt"`
	StatusCode    *int       `json:"status_code,omitempty"`
	Error         *string    `json:"error,omitempty"`
	Payload       string     `json:"payload"`
	ResponseBody  *string    `json:"response_body,omitempty"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	// DeadAt is set once the delivery exhausted maxDeliveryAttempts without
	// succeeding — a dead-lettered delivery the dispatcher no longer retries.
	// Retryable via RetryDelivery, which clears it.
	DeadAt    *time.Time `json:"dead_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// int32PtrToInt converts a *int32 to *int for the domain Delivery type.
func int32PtrToInt(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

// ListDeliveries returns recent deliveries for a subscription, newest first.
// Tenant-scoped via the subscription join, so one tenant can't read another's
// delivery history.
func (s *Service) ListDeliveries(ctx context.Context, subscriptionID, tenantID uuid.UUID, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.q.ListWebhookDeliveries(ctx, dbgen.ListWebhookDeliveriesParams{
		SubscriptionID: subscriptionID,
		TenantID:       tenantID,
		RowLimit:       int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(rows))
	for _, row := range rows {
		out = append(out, Delivery{
			ID:            row.ID,
			EventType:     row.EventType,
			Attempt:       int(row.Attempt),
			StatusCode:    int32PtrToInt(row.StatusCode),
			Error:         row.Error,
			Payload:       row.DPayload,
			ResponseBody:  row.ResponseBody,
			DeliveredAt:   tsPtr(row.DeliveredAt),
			NextAttemptAt: tsPtr(row.NextAttemptAt),
			DeadAt:        tsPtr(row.DeadAt),
			CreatedAt:     row.CreatedAt,
		})
	}
	return out, nil
}

// RetryDelivery re-queues a delivery for immediate redelivery by the dispatcher
// (clears delivered_at + error and sets next_attempt_at to now). Tenant-scoped
// via the subscription join. ErrNotFound when the delivery isn't the tenant's.
func (s *Service) RetryDelivery(ctx context.Context, deliveryID, tenantID uuid.UUID) error {
	n, err := s.q.RetryWebhookDelivery(ctx, dbgen.RetryWebhookDeliveryParams{DeliveryID: deliveryID, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// Enqueue persists a delivery for every matching subscription.
func (s *Service) Enqueue(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ids, err := s.q.GetSubscriptionsForEvent(ctx, dbgen.GetSubscriptionsForEventParams{
		TenantID:  tenantID,
		EventType: eventType,
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.q.InsertDelivery(ctx, dbgen.InsertDeliveryParams{
			SubscriptionID: id,
			EventType:      eventType,
			Payload:        body,
		}); err != nil {
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

// Sweep runs a single dispatch pass over due deliveries — the same work
// RunDispatcher does on each tick. Exposed for ops-triggered sweeps and tests.
func (s *Service) Sweep(ctx context.Context) error { return s.tick(ctx) }

func (s *Service) tick(ctx context.Context) error {
	batch, err := s.q.GetDueDeliveries(ctx)
	if err != nil {
		return err
	}
	for _, it := range batch {
		status, respBody, derr := s.deliver(ctx, it.Url, it.Secret, it.EventType, it.Payload)
		now := time.Now()
		if derr == nil && status >= 200 && status < 300 {
			_ = s.q.MarkDeliverySucceeded(ctx, dbgen.MarkDeliverySucceededParams{
				StatusCode:   int32Ptr(status),
				ResponseBody: strPtr(truncate(respBody, 4000)),
				ID:           it.ID,
			})
			continue
		}
		errStr := ""
		if derr != nil {
			errStr = derr.Error()
		}
		// Give up after maxDeliveryAttempts: a permanently-failing endpoint
		// (dead domain, 404, decommissioned integration) would otherwise retry
		// forever at the 1h backoff ceiling. dead_at marks it dead-lettered;
		// RetryDelivery clears it for a manual re-send.
		if int(it.Attempt)+1 >= maxDeliveryAttempts {
			_ = s.q.DeadLetterDelivery(ctx, dbgen.DeadLetterDeliveryParams{
				StatusCode:   int32Ptr(status),
				ResponseBody: strPtr(truncate(respBody, 4000)),
				Error:        strPtr(errStr),
				ID:           it.ID,
			})
			continue
		}
		backoff := time.Duration(1<<min(int(it.Attempt), 8)) * 30 * time.Second
		if backoff > time.Hour {
			backoff = time.Hour
		}
		_ = s.q.ScheduleDeliveryRetry(ctx, dbgen.ScheduleDeliveryRetryParams{
			StatusCode:    int32Ptr(status),
			ResponseBody:  strPtr(truncate(respBody, 4000)),
			Error:         strPtr(errStr),
			NextAttemptAt: toTS(now.Add(backoff)),
			ID:            it.ID,
		})
	}
	return nil
}

// maxDeliveryAttempts bounds retry so a permanently-failing endpoint doesn't
// retry forever. With the backoff schedule above (~30s doubling to a 1h cap
// after the 7th attempt), 60 attempts spans a little over 2 days of retrying
// before giving up — in line with common webhook-retry conventions.
const maxDeliveryAttempts = 60

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
	r.Get("/webhooks/{id}", h.get)
	r.Delete("/webhooks/{id}", h.disable)
	r.Post("/webhooks/{id}/test", h.test)
	r.Get("/webhooks/{id}/deliveries", h.listDeliveries)
	r.Post("/webhooks/{id}/deliveries/{deliveryID}/retry", h.retryDelivery)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.Get(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

func (h *Handler) listDeliveries(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListDeliveries(r.Context(), id, tenantID, 50)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) retryDelivery(w http.ResponseWriter, r *http.Request) {
	deliveryID, err := uuid.Parse(chi.URLParam(r, "deliveryID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid deliveryID"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RetryDelivery(r.Context(), deliveryID, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Delivery re-queued."})
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
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tenantID // scope from principal, never the body
	if in.URL == "" {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("url required"))
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
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if tid != tenantID {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant mismatch"))
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
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
	scopeTenant, err := httpx.RequireTenant(r)
	if err != nil {
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
	tenantID, url, err := h.Service.Disable(ctx, tx, id, scopeTenant)
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
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.Get(r.Context(), id, tenantID)
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

var _ EventBus = (*Service)(nil)
