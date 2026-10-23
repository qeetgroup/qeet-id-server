// Package webhook lets tenants subscribe to the events in its catalogue and
// receive each as a signed POST. Deliveries are persisted before send so
// retries survive process restarts; a background dispatcher walks the queue.
//
// A delivery's body is an Event. X-Qeet-Signature is "sha256=" and the hex
// HMAC-SHA256, keyed by the subscription's secret, of X-Qeet-Timestamp (Unix
// seconds), a ".", and the body, so a receiver can refuse a stale or replayed
// delivery as well as a forged one. While a rotated secret overlaps the new
// one, the header holds both values, comma-separated.
//
// A subscription whose deliveries fail for autoDisableAfter is disabled, and
// the members who manage the organisation's webhooks are alerted.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhooks/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Subscription is a tenant's webhook endpoint and the event types it receives.
// DisabledReason is "disabled" (by an administrator) or "failing" (by its
// failures); FailingSince is when deliveries to it started failing. Secret is
// returned only on create.
type Subscription struct {
	ID                      uuid.UUID  `json:"id"`
	TenantID                uuid.UUID  `json:"tenant_id"`
	URL                     string     `json:"url"`
	Events                  []string   `json:"events"`
	DisabledAt              *time.Time `json:"disabled_at"`
	DisabledReason          *string    `json:"disabled_reason"`
	FailingSince            *time.Time `json:"failing_since"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at"`
	CreatedAt               time.Time  `json:"created_at"`
	Secret                  string     `json:"secret,omitempty"`
}

// Notifier alerts a person in-app. Satisfied by *notification.Service.
type Notifier interface {
	Notify(ctx context.Context, tenantID, userID uuid.UUID, kind, title, description, href string) error
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// tenant's plan. Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// Service manages the webhook subscriptions.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	client   *http.Client
	gate     PlanGate
	notifier Notifier
	egress   *egress.Policy
	box      *envelope.Cipher
	workerID uuid.UUID
	lease    time.Duration
}

// NewService returns the webhook service.
func NewService(pool *pgxpool.Pool, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{
		pool:     pool,
		q:        dbgen.New(pool),
		client:   policy.HTTPClient(10 * time.Second),
		egress:   policy,
		workerID: uuid.New(),
		lease:    2 * time.Minute,
	}
}

// SetPlanGate wires the plan-feature gate. nil (default) allows all features.
func (s *Service) SetPlanGate(g PlanGate) { s.gate = g }

// SetCipher sets the cipher that encrypts webhook secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetNotifier sets who is alerted when a failing subscription is disabled;
// nil alerts no one.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// Pool returns the connection pool, for handlers that run their own transaction.
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
	i := int32(v) // #nosec G115 -- HTTP status codes only
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

// CreateInput is what Create takes. TenantID is set from the caller's token;
// one sent in the body is ignored.
type CreateInput struct {
	TenantID uuid.UUID `json:"tenant_id"`
	URL      string    `json:"url"`
	Events   []string  `json:"events"`
}

// Create subscribes an endpoint to the events in.Events, which must name at
// least one and only events in the catalogue.
func (s *Service) Create(ctx context.Context, tx pgx.Tx, in CreateInput) (*Subscription, error) {
	if _, err := s.egress.ValidateHTTPURL(in.URL); err != nil {
		return nil, errs.ErrBadRequest.WithDetail("webhook URL is not an allowed outbound destination")
	}
	events, err := subscribableEvents(in.Events)
	if err != nil {
		return nil, err
	}
	in.Events = events
	if err := s.planAllows(ctx, in.TenantID); err != nil {
		return nil, err
	}
	secret, _, err := codes.URLToken()
	if err != nil {
		return nil, err
	}
	if s.box == nil {
		return nil, errs.ErrInternalServer.WithDetail("webhook secret encryption is unavailable")
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(in.TenantID, "webhook-signing", id.String(), []byte(secret))
	if err != nil {
		return nil, err
	}
	var row struct {
		ID         uuid.UUID
		TenantID   uuid.UUID
		URL        string
		Events     []string
		DisabledAt pgtype.Timestamptz
		CreatedAt  time.Time
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO tenant.webhook_subscriptions
		    (id, tenant_id, url, secret, secret_ct, secret_nonce, encryption_version, events)
		VALUES ($1, $2, $3, '', $4, $5, 1, $6)
		RETURNING id, tenant_id, url, events, disabled_at, created_at
	`, id, in.TenantID, in.URL, ciphertext, nonce, in.Events).Scan(
		&row.ID, &row.TenantID, &row.URL, &row.Events, &row.DisabledAt, &row.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &Subscription{
		ID: row.ID, TenantID: row.TenantID, URL: row.URL,
		Events: row.Events, DisabledAt: tsPtr(row.DisabledAt), CreatedAt: row.CreatedAt,
		Secret: secret,
	}, nil
}

// planAllows refuses webhooks to an organisation whose plan doesn't include
// them (Free).
func (s *Service) planAllows(ctx context.Context, tenantID uuid.UUID) error {
	if s.gate == nil {
		return nil
	}
	ok, err := s.gate.FeatureAllowed(ctx, tenantID, "webhooks")
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "webhooks"})
	}
	return nil
}

// List returns the tenant's webhook subscriptions.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Subscription, error) {
	rows, err := s.q.ListWebhookSubscriptions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Subscription, 0, len(rows))
	for _, row := range rows {
		out = append(out, Subscription{
			ID: row.ID, TenantID: row.TenantID, URL: row.Url, Events: row.Events,
			DisabledAt: tsPtr(row.DisabledAt), DisabledReason: row.DisabledReason, FailingSince: tsPtr(row.FailingSince),
			PreviousSecretExpiresAt: tsPtr(row.PreviousSecretExpiresAt), CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

// Get returns one of the tenant's webhook subscriptions.
func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Subscription, error) {
	row, err := s.q.GetWebhookSubscription(ctx, dbgen.GetWebhookSubscriptionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrWebhookNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Subscription{
		ID: row.ID, TenantID: row.TenantID, URL: row.Url, Events: row.Events,
		DisabledAt: tsPtr(row.DisabledAt), DisabledReason: row.DisabledReason, FailingSince: tsPtr(row.FailingSince),
		PreviousSecretExpiresAt: tsPtr(row.PreviousSecretExpiresAt), CreatedAt: row.CreatedAt,
	}, nil
}

// Disable marks the subscription disabled and returns the (tenantID, url)
// so the caller doesn't have to re-query for the audit row.
func (s *Service) Disable(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) (uuid.UUID, string, error) {
	row, err := s.q.WithTx(tx).DisableWebhookSubscription(ctx, dbgen.DisableWebhookSubscriptionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrWebhookNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return row.TenantID, row.Url, nil
}

// Enable turns a disabled subscription back on, with its failures forgotten,
// and returns its URL. Deliveries queued while it was off are then sent.
func (s *Service) Enable(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) (string, error) {
	if err := s.planAllows(ctx, tenantID); err != nil {
		return "", err
	}
	url, err := s.q.WithTx(tx).EnableWebhookSubscription(ctx, dbgen.EnableWebhookSubscriptionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrWebhookNotFound
	}
	return url, err
}

// SecretRotationOverlap is how long a rotated-out secret goes on signing
// deliveries alongside the new one.
const SecretRotationOverlap = 24 * time.Hour

// RotateSecret replaces the subscription's signing secret and returns the new
// one, shown only here, and when the old one stops signing. Rotating again
// within the overlap ends the older secret's at once.
func (s *Service) RotateSecret(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) (string, time.Time, error) {
	if s.box == nil {
		return "", time.Time{}, errs.ErrInternalServer.WithDetail("webhook secret encryption is unavailable")
	}
	q := s.q.WithTx(tx)
	cur, err := q.LockWebhookSecret(ctx, dbgen.LockWebhookSecretParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, errs.ErrWebhookNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	previousCT, previousNonce := cur.SecretCt, cur.SecretNonce
	if len(previousCT) == 0 {
		// A secret stored before encryption is sealed as it steps aside.
		if previousCT, previousNonce, err = s.box.Seal(tenantID, "webhook-signing", id.String(), []byte(cur.Secret)); err != nil {
			return "", time.Time{}, err
		}
	}
	secret, _, err := codes.URLToken()
	if err != nil {
		return "", time.Time{}, err
	}
	ct, nonce, err := s.box.Seal(tenantID, "webhook-signing", id.String(), []byte(secret))
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().UTC().Add(SecretRotationOverlap)
	err = q.RotateWebhookSecret(ctx, dbgen.RotateWebhookSecretParams{
		SecretCt: ct, SecretNonce: nonce, PreviousCt: previousCT, PreviousNonce: previousNonce,
		PreviousExpiresAt: pgtype.Timestamptz{Time: until, Valid: true}, ID: id, TenantID: tenantID,
	})
	return secret, until, err
}

// Delivery is one event's dispatch to a subscription, with the payload and
// response for the admin delivery viewer. DeadAt is set once it has failed
// maxDeliveryAttempts times; RetryDelivery clears it.
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
	DeadAt        *time.Time `json:"dead_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
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

// RetryDelivery re-queues one of the tenant's deliveries for immediate
// redelivery, clearing delivered_at, dead_at and error. It fails with
// ErrWebhookDeliveryNotFound when the delivery isn't the tenant's or a
// dispatcher currently holds its lease.
func (s *Service) RetryDelivery(ctx context.Context, deliveryID, tenantID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE tenant.webhook_deliveries AS delivery
		SET delivered_at = NULL, dead_at = NULL, error = NULL, next_attempt_at = NOW(),
		    lease_owner = NULL, lease_until = NULL
		FROM tenant.webhook_subscriptions AS subscription
		WHERE delivery.id = $1 AND delivery.subscription_id = subscription.id
		  AND subscription.tenant_id = $2
		  AND (delivery.lease_until IS NULL OR delivery.lease_until <= NOW())
	`, deliveryID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errs.ErrWebhookDeliveryNotFound
	}
	return nil
}

// Enqueue persists a delivery for every matching subscription.
func (s *Service) Enqueue(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error {
	return s.enqueue(ctx, s.q, tenantID, eventType, payload)
}

// EnqueueTx is Enqueue inside the caller's transaction, so the deliveries are
// committed, or rolled back, with the change they describe.
func (s *Service) EnqueueTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, eventType string, payload any) error {
	return s.enqueue(ctx, s.q.WithTx(tx), tenantID, eventType, payload)
}

func (s *Service) enqueue(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.queue(ctx, q, Event{ID: uuid.New(), Type: eventType, TenantID: tenantID, OccurredAt: time.Now().UTC(), Data: data})
}

// SendTest queues a TestEvent for sub alone, whichever events it names.
func (s *Service) SendTest(ctx context.Context, sub *Subscription) error {
	data, err := json.Marshal(map[string]any{"subscription_id": sub.ID})
	if err != nil {
		return err
	}
	e := Event{ID: uuid.New(), Type: TestEvent, TenantID: sub.TenantID, OccurredAt: time.Now().UTC(), Data: data}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.q.InsertDelivery(ctx, dbgen.InsertDeliveryParams{SubscriptionID: sub.ID, EventID: e.ID, EventType: e.Type, Payload: body})
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
		WITH candidates AS (
			SELECT delivery.id
			FROM tenant.webhook_deliveries AS delivery
			JOIN tenant.webhook_subscriptions AS subscription ON subscription.id = delivery.subscription_id
			WHERE delivery.delivered_at IS NULL AND delivery.dead_at IS NULL
			  AND delivery.next_attempt_at <= NOW()
			  AND (delivery.lease_until IS NULL OR delivery.lease_until <= NOW())
			  AND subscription.disabled_at IS NULL
			ORDER BY delivery.created_at
			LIMIT 20
			FOR UPDATE OF delivery SKIP LOCKED
		)
		UPDATE tenant.webhook_deliveries AS delivery
		SET lease_owner = $1, lease_until = $2
		FROM candidates, tenant.webhook_subscriptions AS subscription
		WHERE delivery.id = candidates.id AND subscription.id = delivery.subscription_id
		RETURNING delivery.id, delivery.subscription_id, delivery.event_type,
		          delivery.payload, delivery.attempt, subscription.id,
		          subscription.tenant_id, subscription.url, subscription.secret,
		          subscription.secret_ct, subscription.secret_nonce,
		          subscription.previous_secret_ct, subscription.previous_secret_nonce,
		          subscription.previous_secret_expires_at
	`, s.workerID, time.Now().UTC().Add(s.lease))
	if err != nil {
		return err
	}
	type dueDelivery struct {
		ID, SubscriptionID, SecretID, TenantID uuid.UUID
		EventType, URL, LegacySecret           string
		Payload, SecretCT, SecretNonce         []byte
		PreviousCT, PreviousNonce              []byte
		PreviousUntil                          pgtype.Timestamptz
		Attempt                                int32
	}
	var batch []dueDelivery
	for rows.Next() {
		var item dueDelivery
		if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.EventType, &item.Payload, &item.Attempt,
			&item.SecretID, &item.TenantID, &item.URL, &item.LegacySecret, &item.SecretCT, &item.SecretNonce,
			&item.PreviousCT, &item.PreviousNonce, &item.PreviousUntil); err != nil {
			return err
		}
		batch = append(batch, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, it := range batch {
		secretValue := it.LegacySecret
		if len(it.SecretCT) > 0 {
			if s.box == nil {
				return errors.New("webhook secret encryption is unavailable")
			}
			plain, openErr := s.box.Open(it.TenantID, "webhook-signing", it.SecretID.String(), it.SecretCT, it.SecretNonce)
			if openErr != nil {
				return openErr
			}
			secretValue = string(plain)
		} else if secretValue != "" && s.box != nil {
			ct, nonce, sealErr := s.box.Seal(it.TenantID, "webhook-signing", it.SecretID.String(), []byte(secretValue))
			if sealErr != nil {
				return sealErr
			}
			if _, updateErr := s.pool.Exec(ctx, `
				UPDATE tenant.webhook_subscriptions
				SET secret = '', secret_ct = $2, secret_nonce = $3, encryption_version = 1
				WHERE id = $1 AND secret_ct IS NULL
			`, it.SecretID, ct, nonce); updateErr != nil {
				return updateErr
			}
		}
		secrets := []string{secretValue}
		if it.PreviousUntil.Valid && time.Now().Before(it.PreviousUntil.Time) {
			previous, openErr := s.box.Open(it.TenantID, "webhook-signing", it.SecretID.String(), it.PreviousCT, it.PreviousNonce)
			if openErr != nil {
				slog.Warn("webhook previous secret unreadable; signing with the current one only", "subscription_id", it.SubscriptionID, "err", openErr)
			} else {
				secrets = append(secrets, string(previous))
			}
		}
		status, respBody, derr := s.deliver(ctx, it.ID, it.URL, secrets, it.EventType, it.Payload)
		now := time.Now()
		if derr == nil && status >= 200 && status < 300 {
			if _, err := s.pool.Exec(ctx, `
				UPDATE tenant.webhook_deliveries
				SET delivered_at = NOW(), status_code = $3, response_body = $4,
				    attempt = attempt + 1, error = NULL,
				    lease_owner = NULL, lease_until = NULL
				WHERE id = $1 AND lease_owner = $2
			`, it.ID, s.workerID, int32Ptr(status), strPtr(truncate(respBody, 4000))); err != nil {
				return err
			}
			if _, err := s.pool.Exec(ctx, `
				UPDATE tenant.webhook_subscriptions SET failing_since = NULL WHERE id = $1 AND failing_since IS NOT NULL
			`, it.SubscriptionID); err != nil {
				return err
			}
			continue
		}
		if err := s.noteFailure(ctx, it.SubscriptionID, it.TenantID); err != nil {
			slog.Warn("webhook failure not recorded", "subscription_id", it.SubscriptionID, "err", err)
		}
		errStr := ""
		if derr != nil {
			errStr = derr.Error()
		}
		// Give up after maxDeliveryAttempts, or at once when the endpoint
		// refused the delivery itself: a permanently-failing endpoint (dead
		// domain, decommissioned integration) would otherwise retry forever at
		// the 1h backoff ceiling. dead_at marks it dead-lettered; RetryDelivery
		// clears it for a manual re-send.
		if int(it.Attempt)+1 >= maxDeliveryAttempts || !retryable(status) {
			if _, err := s.pool.Exec(ctx, `
				UPDATE tenant.webhook_deliveries
				SET attempt = attempt + 1, status_code = $3, response_body = $4,
				    error = $5, dead_at = NOW(), lease_owner = NULL, lease_until = NULL
				WHERE id = $1 AND lease_owner = $2
			`, it.ID, s.workerID, int32Ptr(status), strPtr(truncate(respBody, 4000)), strPtr(errStr)); err != nil {
				return err
			}
			continue
		}
		backoff := time.Duration(1<<min(int(it.Attempt), 8)) * 30 * time.Second
		if backoff > time.Hour {
			backoff = time.Hour
		}
		backoff = jittered(backoff)
		if _, err := s.pool.Exec(ctx, `
			UPDATE tenant.webhook_deliveries
			SET attempt = attempt + 1, status_code = $3, response_body = $4,
			    error = $5, next_attempt_at = $6,
			    lease_owner = NULL, lease_until = NULL
			WHERE id = $1 AND lease_owner = $2
		`, it.ID, s.workerID, int32Ptr(status), strPtr(truncate(respBody, 4000)), strPtr(errStr), now.Add(backoff)); err != nil {
			return err
		}
	}
	return nil
}

// maxDeliveryAttempts bounds retry so a permanently-failing endpoint doesn't
// retry forever. With the backoff schedule above (~30s doubling to a 1h cap
// after the 7th attempt), 60 attempts spans a little over 2 days of retrying
// before giving up — in line with common webhook-retry conventions.
const maxDeliveryAttempts = 60

// retryable reports whether a delivery answered status (0: no answer) may
// succeed if sent again. A 4xx other than 408 and 429 is the endpoint refusing
// the delivery itself, and would be refused again.
func retryable(status int) bool {
	if status < 400 || status >= 500 {
		return true
	}
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests
}

// jittered returns d less a random part of up to half of it, so deliveries
// that failed together don't all retry together.
func jittered(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d/2)+1))
	if err != nil {
		return d
	}
	return d - time.Duration(n.Int64())
}

// autoDisableAfter is how long deliveries to a subscription may fail, with no
// success between, before it is disabled.
const autoDisableAfter = 3 * 24 * time.Hour

// noteFailure records that a delivery to subscriptionID failed. Once its
// deliveries have failed for autoDisableAfter it is disabled, audited, and the
// organisation's webhook managers are alerted.
func (s *Service) noteFailure(ctx context.Context, subscriptionID, tenantID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var (
		url          string
		failingSince time.Time
		disabled     bool
	)
	err = tx.QueryRow(ctx, `
		UPDATE tenant.webhook_subscriptions
		SET failing_since = COALESCE(failing_since, NOW()),
		    disabled_at = CASE WHEN failing_since <= $3 THEN NOW() END,
		    disabled_reason = CASE WHEN failing_since <= $3 THEN 'failing' END
		WHERE id = $1 AND tenant_id = $2 AND disabled_at IS NULL
		RETURNING url, failing_since, disabled_at IS NOT NULL
	`, subscriptionID, tenantID, time.Now().Add(-autoDisableAfter)).Scan(&url, &failingSince, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already disabled
	}
	if err != nil {
		return err
	}
	if !disabled {
		return tx.Commit(ctx)
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "system", Action: "webhook.subscription_auto_disabled",
		ResourceType: "webhook_subscription", ResourceID: &subscriptionID,
		Metadata: map[string]any{"url": url, "failing_since": failingSince},
	}); err != nil {
		return err
	}
	managers, err := s.q.WithTx(tx).ListWebhookManagers(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if s.notifier != nil {
		description := "Deliveries to " + url + " failed for 3 days, so the webhook was turned off. Fix the endpoint, then turn the webhook back on."
		for _, userID := range managers {
			if err := s.notifier.Notify(ctx, tenantID, userID, "alert", "Webhook turned off", description, "/developer/webhooks/"+subscriptionID.String()); err != nil {
				slog.Warn("notify webhook disabled", "subscription_id", subscriptionID, "err", err)
			}
		}
	}
	return nil
}

// deliver posts body to url, signed with each of secrets: the current one,
// and a rotated-out one while it overlaps.
func (s *Service) deliver(ctx context.Context, deliveryID uuid.UUID, url string, secrets []string, eventType string, body []byte) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Qeet-Event", eventType)
	req.Header.Set("X-Qeet-Delivery-ID", deliveryID.String())
	req.Header.Set("X-Qeet-Timestamp", timestamp)
	signatures := make([]string, len(secrets))
	for i, secret := range secrets {
		signatures[i] = "sha256=" + sign(secret, timestamp, body)
	}
	req.Header.Set("X-Qeet-Signature", strings.Join(signatures, ","))
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

// sign returns the hex HMAC-SHA256 of timestamp, ".", and body, keyed by
// secret.
func sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// Handler serves the webhook HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the webhook routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/webhooks", h.create)
	r.Get("/tenants/{tenantID}/webhooks", h.list)
	r.Get("/tenants/{tenantID}/webhooks/events", h.events)
	r.Post("/tenants/{tenantID}/webhooks/{id}/enable", h.enable)
	r.Post("/tenants/{tenantID}/webhooks/{id}/rotate-secret", h.rotateSecret)
	r.Get("/webhooks/{id}", h.get)
	r.Delete("/webhooks/{id}", h.disable)
	r.Post("/webhooks/{id}/test", h.test)
	r.Get("/webhooks/{id}/deliveries", h.listDeliveries)
	r.Post("/webhooks/{id}/deliveries/{deliveryID}/retry", h.retryDelivery)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrWebhookInvalidID)
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
		httpx.WriteError(w, r, errs.ErrWebhookInvalidID)
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
		httpx.WriteError(w, r, errs.ErrWebhookInvalidID)
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
		httpx.WriteError(w, r, errs.ErrWebhookURLRequired)
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
	actorID, actorType := audit.ActorOf(r).Identity()
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
		httpx.WriteError(w, r, errs.ErrWebhookInvalidID)
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if tid != tenantID {
		httpx.WriteError(w, r, errs.ErrWebhookTenantMismatch)
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
		httpx.WriteError(w, r, errs.ErrWebhookInvalidID)
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
	actorID, actorType := audit.ActorOf(r).Identity()
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
		httpx.WriteError(w, r, errs.ErrWebhookInvalidID)
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
	if err := h.Service.SendTest(r.Context(), sub); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"queued": true, "subscription": sub.ID})
}

// pathSubscription returns the {tenantID} and {id} of a tenant-path webhook
// route.
func pathSubscription(r *http.Request) (tenantID, id uuid.UUID, err error) {
	if tenantID, err = httpx.PathTenantOr(r, errs.ErrWebhookInvalidID, errs.ErrWebhookTenantMismatch); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if id, err = uuid.Parse(chi.URLParam(r, "id")); err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrWebhookInvalidID
	}
	return tenantID, id, nil
}

// enable turns a disabled subscription back on.
func (h *Handler) enable(w http.ResponseWriter, r *http.Request) {
	tenantID, id, err := pathSubscription(r)
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
	url, err := h.Service.Enable(ctx, tx, id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.audit(r, tx, tenantID, id, "webhook.subscription_enabled", map[string]any{"url": url}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.Get(ctx, id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

// rotateSecret replaces a subscription's signing secret.
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	tenantID, id, err := pathSubscription(r)
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
	secret, until, err := h.Service.RotateSecret(ctx, tx, id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.audit(r, tx, tenantID, id, "webhook.secret_rotated", map[string]any{"previous_secret_expires_at": until}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"secret": secret, "previous_secret_expires_at": until})
}

// audit records action on subscription id as the caller's.
func (h *Handler) audit(r *http.Request, tx pgx.Tx, tenantID, id uuid.UUID, action string, metadata map[string]any) error {
	actorID, actorType := audit.ActorOf(r).Identity()
	return audit.Record(r.Context(), tx, audit.Event{
		TenantID: &tenantID, ActorUserID: actorID, ActorType: actorType, Action: action,
		ResourceType: "webhook_subscription", ResourceID: &id,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r), Metadata: metadata,
	})
}

// events lists the event catalogue.
func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.PathTenantOr(r, errs.ErrWebhookInvalidID, errs.ErrWebhookTenantMismatch); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": Events})
}

// EventBus is satisfied by webhook.Service so other modules can publish
// without depending on the concrete type.
type EventBus interface {
	Enqueue(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error
}

var _ EventBus = (*Service)(nil)
