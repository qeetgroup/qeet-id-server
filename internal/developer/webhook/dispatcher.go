package webhook

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/requestsig"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// int32Ptr converts an int to *int32 for sqlc status-code params (nil when 0).
func int32Ptr(v int) *int32 {
	if v == 0 {
		return nil
	}
	i := int32(v) // #nosec G115 -- HTTP status codes only
	return &i
}

// errNotInPlan is the error recorded on a delivery dead-lettered because the
// organization's plan no longer includes webhooks.
const errNotInPlan = "not sent: the organization's plan does not include webhooks"

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
	batch, err := s.q.ClaimDueDeliveries(ctx, dbgen.ClaimDueDeliveriesParams{LeaseOwner: s.workerID, LeaseUntil: time.Now().UTC().Add(s.lease)})
	if err != nil {
		return err
	}
	plans := map[uuid.UUID]bool{} // organizations whose plan includes webhooks, asked once a batch
	for _, it := range batch {
		allowed, known := plans[it.OrganizationID]
		if !known {
			if allowed, err = s.planIncludesWebhooks(ctx, it.OrganizationID); err != nil {
				return err
			}
			plans[it.OrganizationID] = allowed
		}
		if !allowed {
			// Set up on a plan that has since lapsed: the delivery is
			// dead-lettered unsent, and can be sent again once paid for.
			if err := s.q.DeadLetterUnsent(ctx, dbgen.DeadLetterUnsentParams{Error: new(errNotInPlan), ID: it.ID, LeaseOwner: s.workerID}); err != nil {
				return err
			}
			continue
		}
		current, openErr := s.box.Open(it.OrganizationID, "webhook-signing", it.SubscriptionID.String(), it.SecretCt, it.SecretNonce)
		if openErr != nil {
			return openErr
		}
		secrets := []string{string(current)}
		if it.PreviousSecretExpiresAt != nil && time.Now().Before(*it.PreviousSecretExpiresAt) {
			previous, openErr := s.box.Open(it.OrganizationID, "webhook-signing", it.SubscriptionID.String(), it.PreviousSecretCt, it.PreviousSecretNonce)
			if openErr != nil {
				slog.Warn("webhook previous secret unreadable; signing with the current one only", "subscription_id", it.SubscriptionID, "err", openErr)
			} else {
				secrets = append(secrets, string(previous))
			}
		}
		started := time.Now()
		status, respBody, derr := s.deliver(ctx, it.ID, it.Url, secrets, it.EventType, it.Payload)
		now := time.Now()
		s.recordAttempt(ctx, it.OrganizationID, it.ID, status, now.Sub(started), derr)
		body := strutil.NilIfEmpty(strutil.Truncate(respBody, 4000))
		if derr == nil && status >= 200 && status < 300 {
			if err := s.q.MarkDeliverySucceeded(ctx, dbgen.MarkDeliverySucceededParams{
				StatusCode: int32Ptr(status), ResponseBody: body, ID: it.ID, LeaseOwner: s.workerID,
			}); err != nil {
				return err
			}
			deliveries.WithLabelValues("delivered").Inc()
			if err := s.q.ClearSubscriptionFailing(ctx, dbgen.ClearSubscriptionFailingParams{ID: it.SubscriptionID, OrganizationID: it.OrganizationID}); err != nil {
				return err
			}
			continue
		}
		if err := s.noteFailure(ctx, it.SubscriptionID, it.OrganizationID); err != nil {
			slog.Warn("webhook failure not recorded", "subscription_id", it.SubscriptionID, "err", err)
		}
		var failure *string
		if derr != nil {
			failure = strutil.NilIfEmpty(derr.Error())
		}
		// Give up after maxDeliveryAttempts, or at once when the endpoint refused the delivery itself, so a
		// dead endpoint doesn't retry forever at the 1h ceiling. dead_at marks it dead-lettered;
		// RetryDelivery clears it for a manual re-send.
		if int(it.Attempt)+1 >= maxDeliveryAttempts || !retryable(status) {
			if err := s.q.DeadLetterDelivery(ctx, dbgen.DeadLetterDeliveryParams{
				StatusCode: int32Ptr(status), ResponseBody: body, Error: failure, ID: it.ID, LeaseOwner: s.workerID,
			}); err != nil {
				return err
			}
			deliveries.WithLabelValues("dead").Inc()
			continue
		}
		backoff := time.Duration(1<<min(int(it.Attempt), 8)) * 30 * time.Second
		if backoff > time.Hour {
			backoff = time.Hour
		}
		backoff = jittered(backoff)
		if err := s.q.ScheduleDeliveryRetry(ctx, dbgen.ScheduleDeliveryRetryParams{
			StatusCode: int32Ptr(status), ResponseBody: body, Error: failure, NextAttemptAt: now.Add(backoff),
			ID: it.ID, LeaseOwner: s.workerID,
		}); err != nil {
			return err
		}
		deliveries.WithLabelValues("retry").Inc()
	}
	return nil
}

// recordAttempt keeps one try at a delivery. Losing it costs the history
// only, so a failure is logged, not returned.
func (s *Service) recordAttempt(ctx context.Context, organizationID, deliveryID uuid.UUID, status int, took time.Duration, derr error) {
	var code *int32
	if status > 0 {
		code = int32Ptr(status)
	}
	var failure *string
	if derr != nil {
		failure = strutil.NilIfEmpty(strutil.Truncate(derr.Error(), 1000))
	}
	ms := min(took.Milliseconds(), math.MaxInt32)
	if err := s.q.InsertDeliveryAttempt(ctx, dbgen.InsertDeliveryAttemptParams{
		OrganizationID: organizationID, DeliveryID: deliveryID, StatusCode: code, DurationMs: int32(ms), Error: failure, // #nosec G115 -- capped above
	}); err != nil {
		slog.Warn("webhook attempt not recorded", "delivery_id", deliveryID, "err", err)
	}
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
// organization's webhook managers are alerted.
func (s *Service) noteFailure(ctx context.Context, subscriptionID, organizationID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.NoteSubscriptionFailure(ctx, dbgen.NoteSubscriptionFailureParams{
		DisableBefore: time.Now().Add(-autoDisableAfter), ID: subscriptionID, OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already disabled
	}
	if err != nil {
		return err
	}
	if !row.Disabled {
		return tx.Commit(ctx)
	}
	if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(organizationID, "webhook.subscription_auto_disabled", "webhook_subscription", subscriptionID,
		map[string]any{"url": row.Url, "failing_since": postgres.ZeroIfNull(row.FailingSince)})); err != nil {
		return err
	}
	managers, err := q.ListWebhookManagers(ctx, organizationID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	description := "Deliveries to " + row.Url + " failed for 3 days, so the webhook was turned off. Fix the endpoint, then turn the webhook back on."
	for _, userID := range managers {
		if err := s.notifier.Notify(ctx, organizationID, userID, "alert", "Webhook turned off", description, "/developer/webhooks/"+subscriptionID.String()); err != nil {
			slog.Warn("notify webhook disabled", "subscription_id", subscriptionID, "err", err)
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
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Qeet-Event", eventType)
	req.Header.Set("X-Qeet-Delivery-ID", deliveryID.String())
	requestsig.SetHeaders(req.Header, time.Now(), body, secrets...)
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
