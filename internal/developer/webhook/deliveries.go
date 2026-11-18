package webhook

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

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

// ListDeliveries returns a page of up to limit of a subscription's deliveries
// (paging.Clamp: 50 when unset, at most 200), newest first, after the cursor,
// of status when given (delivered, pending, retrying or dead), and the next
// page's cursor. Organization-scoped via the subscription join, so one
// organization can't read another's delivery history.
func (s *Service) ListDeliveries(ctx context.Context, subscriptionID, organizationID uuid.UUID, limit int, after paging.Cursor, status string) ([]Delivery, string, error) {
	limit = paging.Clamp(limit, 50, 200)
	params := dbgen.ListWebhookDeliveriesParams{
		SubscriptionID: subscriptionID,
		OrganizationID: organizationID,
		RowLimit:       int32(limit + 1), // #nosec G115 -- at most 201
	}
	switch status {
	case "":
	case "delivered", "pending", "retrying", "dead":
		params.Status = &status
	default:
		return nil, "", errs.ErrBadRequest.WithDetail("status is delivered, pending, retrying or dead")
	}
	params.BeforeTs, params.BeforeID = after.Before()
	rows, err := s.q.ListWebhookDeliveries(ctx, params)
	if err != nil {
		return nil, "", err
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
			DeliveredAt:   row.DeliveredAt,
			NextAttemptAt: row.NextAttemptAt,
			DeadAt:        row.DeadAt,
			CreatedAt:     row.CreatedAt,
		})
	}
	page, next := paging.Next(out, limit, func(d Delivery) (time.Time, uuid.UUID) { return d.CreatedAt, d.ID })
	return page, next, nil
}

// retryBatch is how many given-up deliveries one bulk retry re-queues.
const retryBatch = 1000

// RetryDead re-queues, with a fresh budget of attempts, up to retryBatch of
// the subscription's given-up deliveries, recorded as actor's, and returns
// how many.
func (s *Service) RetryDead(ctx context.Context, subscriptionID, organizationID uuid.UUID, actor audit.Actor) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if _, err := q.GetWebhookSubscription(ctx, dbgen.GetWebhookSubscriptionParams{ID: subscriptionID, OrganizationID: organizationID}); errors.Is(err, pgx.ErrNoRows) {
		return 0, errs.ErrWebhookNotFound
	} else if err != nil {
		return 0, err
	}
	n, err := q.RetryDeadDeliveries(ctx, dbgen.RetryDeadDeliveriesParams{SubscriptionID: subscriptionID, OrganizationID: organizationID, RowLimit: retryBatch})
	if err != nil {
		return 0, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "webhook.deliveries_retried", "webhook_subscription", subscriptionID,
		map[string]any{"requeued": n})); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

// Attempt is one try at a delivery: when, the answer's status (none when the
// endpoint gave no answer), how long it took, and what went wrong.
type Attempt struct {
	AttemptedAt time.Time `json:"attempted_at"`
	StatusCode  *int      `json:"status_code"`
	DurationMS  int       `json:"duration_ms"`
	Error       *string   `json:"error"`
}

// Attempts returns a delivery's attempts, oldest first.
func (s *Service) Attempts(ctx context.Context, subscriptionID, deliveryID, organizationID uuid.UUID) ([]Attempt, error) {
	rows, err := s.q.ListDeliveryAttempts(ctx, dbgen.ListDeliveryAttemptsParams{DeliveryID: deliveryID, SubscriptionID: subscriptionID, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	out := make([]Attempt, len(rows))
	for i, r := range rows {
		out[i] = Attempt{AttemptedAt: r.AttemptedAt, StatusCode: int32PtrToInt(r.StatusCode), DurationMS: int(r.DurationMs), Error: r.Error}
	}
	return out, nil
}

// RetryDelivery re-queues one of an organization's subscription's deliveries for
// immediate redelivery, clearing delivered_at, dead_at and error. A delivery
// that had finished, delivered or given up, starts a fresh budget of attempts;
// one still retrying keeps its count. It fails with ErrWebhookDeliveryNotFound
// when the delivery isn't that subscription's, the subscription isn't the
// organization's, or a dispatcher currently holds its lease.
func (s *Service) RetryDelivery(ctx context.Context, subscriptionID, deliveryID, organizationID uuid.UUID) error {
	n, err := s.q.RetryWebhookDelivery(ctx, dbgen.RetryWebhookDeliveryParams{
		DeliveryID: deliveryID, SubscriptionID: subscriptionID, OrganizationID: organizationID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDeliveryNotFound
	}
	return nil
}
