package webhook

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Subscription is an organization's webhook endpoint and the event types it receives.
// DisabledReason is "disabled" (by an administrator) or "failing" (by its
// failures); FailingSince is when deliveries to it started failing. Secret is
// returned only on create.
type Subscription struct {
	ID                      uuid.UUID  `json:"id"`
	OrganizationID          uuid.UUID  `json:"organization_id"`
	URL                     string     `json:"url"`
	Events                  []string   `json:"events"`
	DisabledAt              *time.Time `json:"disabled_at"`
	DisabledReason          *string    `json:"disabled_reason"`
	FailingSince            *time.Time `json:"failing_since"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at"`
	CreatedAt               time.Time  `json:"created_at"`
	Secret                  string     `json:"secret,omitempty"`
	// DisabledBy is the administrator who disabled it.
	DisabledBy *uuid.UUID `json:"disabled_by,omitempty"`
	// LastDeliveredAt and LastStatusCode are its latest delivery and answer;
	// Counts its deliveries yet to go and given up.
	LastDeliveredAt *time.Time      `json:"last_delivered_at"`
	LastStatusCode  *int            `json:"last_status_code"`
	Counts          *DeliveryCounts `json:"counts,omitempty"`
}

// DeliveryCounts are a subscription's deliveries not yet tried (held while it
// is disabled), retrying, and given up.
type DeliveryCounts struct {
	Pending  int `json:"pending"`
	Retrying int `json:"retrying"`
	GaveUp   int `json:"gave_up"`
}

// CreateInput is what Create takes. OrganizationID is set from the caller's token;
// one sent in the body is ignored.
type CreateInput struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	URL            string    `json:"url"`
	Events         []string  `json:"events"`
}

// Create subscribes an endpoint to the events in.Events, which must name at
// least one and only events in the catalogue, recorded as actor's, who is
// noted as its creator.
func (s *Service) Create(ctx context.Context, in CreateInput, actor audit.Actor) (*Subscription, error) {
	if in.URL == "" {
		return nil, ErrURLRequired
	}
	if _, err := s.egress.ValidateHTTPURL(in.URL); err != nil {
		return nil, ErrURLNotAllowed
	}
	events, err := subscribableEvents(in.Events)
	if err != nil {
		return nil, err
	}
	if err := s.planAllows(ctx, in.OrganizationID); err != nil {
		return nil, err
	}
	secret, _, err := codes.URLToken()
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(in.OrganizationID, "webhook-signing", id.String(), []byte(secret))
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateWebhookSubscription(ctx, dbgen.CreateWebhookSubscriptionParams{
		ID: id, OrganizationID: in.OrganizationID, Url: in.URL, SecretCt: ciphertext, SecretNonce: nonce,
		Events: events, CreatedBy: actor.UserID,
	})
	if err != nil {
		return nil, err
	}
	sub := &Subscription{
		ID: row.ID, OrganizationID: row.OrganizationID, URL: row.Url,
		Events: row.Events, DisabledAt: row.DisabledAt, CreatedAt: row.CreatedAt,
		Secret: secret,
	}
	if err := audit.Record(ctx, tx, actor.Event(sub.OrganizationID, "webhook.subscription_created", "webhook_subscription", sub.ID,
		map[string]any{"url": sub.URL, "events": sub.Events})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sub, nil
}

// planAllows refuses webhooks to an organization whose plan doesn't include
// them (Free).
func (s *Service) planAllows(ctx context.Context, organizationID uuid.UUID) error {
	ok, err := s.planIncludesWebhooks(ctx, organizationID)
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "webhooks"})
	}
	return nil
}

// planIncludesWebhooks reports whether the organization's plan includes
// webhooks; with no gate set, every plan does.
func (s *Service) planIncludesWebhooks(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	return s.gate.FeatureAllowed(ctx, organizationID, "webhooks")
}

// List returns the organization's webhook subscriptions.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Subscription, error) {
	rows, err := s.q.ListWebhookSubscriptions(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Subscription, 0, len(rows))
	for _, row := range rows {
		out = append(out, *subscriptionOf(dbgen.GetWebhookSubscriptionRow(row)))
	}
	return out, nil
}

// subscriptionOf maps a stored subscription with its delivery figures.
func subscriptionOf(row dbgen.GetWebhookSubscriptionRow) *Subscription {
	sub := &Subscription{
		ID: row.ID, OrganizationID: row.OrganizationID, URL: row.Url, Events: row.Events,
		DisabledAt: row.DisabledAt, DisabledReason: row.DisabledReason, FailingSince: row.FailingSince,
		PreviousSecretExpiresAt: row.PreviousSecretExpiresAt, CreatedAt: row.CreatedAt,
		LastDeliveredAt: row.LastDeliveredAt, LastStatusCode: int32PtrToInt(row.LastStatusCode),
		Counts: &DeliveryCounts{Pending: int(row.Pending), Retrying: int(row.Retrying), GaveUp: int(row.GaveUp)},
	}
	sub.DisabledBy = row.DisabledBy
	return sub
}

// Get returns one of the organization's webhook subscriptions.
func (s *Service) Get(ctx context.Context, id, organizationID uuid.UUID) (*Subscription, error) {
	row, err := s.q.GetWebhookSubscription(ctx, dbgen.GetWebhookSubscriptionParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return subscriptionOf(row), nil
}

// UpdateInput changes a subscription's URL, its events, or both.
type UpdateInput struct {
	URL    *string   `json:"url"`
	Events *[]string `json:"events"`
}

// Update changes the subscription's URL or events, each checked as Create
// checks them, and returns it as it is now. It is recorded as actor's, with
// what changed.
func (s *Service) Update(ctx context.Context, id, organizationID uuid.UUID, in UpdateInput, actor audit.Actor) (*Subscription, error) {
	if in.URL != nil {
		url := strings.TrimSpace(*in.URL)
		if url == "" {
			return nil, ErrURLRequired
		}
		if _, err := s.egress.ValidateHTTPURL(url); err != nil {
			return nil, ErrURLNotAllowed
		}
		in.URL = &url
	}
	if in.Events != nil {
		events, err := subscribableEvents(*in.Events)
		if err != nil {
			return nil, err
		}
		in.Events = &events
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.GetWebhookSubscription(ctx, dbgen.GetWebhookSubscriptionParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	before := subscriptionOf(row)
	var events []string
	if in.Events != nil {
		events = *in.Events
	}
	if _, err := q.UpdateWebhookSubscription(ctx, dbgen.UpdateWebhookSubscriptionParams{
		ID: id, OrganizationID: organizationID, Url: in.URL, Events: events,
	}); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	row, err = q.GetWebhookSubscription(ctx, dbgen.GetWebhookSubscriptionParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	after := subscriptionOf(row)
	changes := map[string]any{}
	if before.URL != after.URL {
		changes["url"] = map[string]any{"from": before.URL, "to": after.URL}
	}
	if !slices.Equal(before.Events, after.Events) {
		changes["events"] = map[string]any{"from": before.Events, "to": after.Events}
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "webhook.subscription_updated", "webhook_subscription", id,
		map[string]any{"changes": changes})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return after, nil
}

// Disable marks one of the organization's subscriptions disabled by actor,
// recorded as theirs.
func (s *Service) Disable(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	url, err := s.q.WithTx(tx).DisableWebhookSubscription(ctx, dbgen.DisableWebhookSubscriptionParams{ID: id, OrganizationID: organizationID, DisabledBy: actor.UserID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "webhook.subscription_disabled", "webhook_subscription", id,
		map[string]any{"url": url})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Enable turns a disabled subscription back on, with its failures forgotten,
// recorded as actor's, and returns it. Deliveries queued while it was off are
// then sent.
func (s *Service) Enable(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) (*Subscription, error) {
	if err := s.planAllows(ctx, organizationID); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	url, err := q.EnableWebhookSubscription(ctx, dbgen.EnableWebhookSubscriptionParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "webhook.subscription_enabled", "webhook_subscription", id,
		map[string]any{"url": url})); err != nil {
		return nil, err
	}
	row, err := q.GetWebhookSubscription(ctx, dbgen.GetWebhookSubscriptionParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return subscriptionOf(row), nil
}

// SecretRotationOverlap is how long a rotated-out secret goes on signing
// deliveries alongside the new one.
const SecretRotationOverlap = 24 * time.Hour

// RotateSecret replaces the subscription's signing secret, recorded as
// actor's, and returns the new one, shown only here, and when the old one
// stops signing. Rotating again within the overlap ends the older secret's at
// once.
func (s *Service) RotateSecret(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) (string, time.Time, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	cur, err := q.LockWebhookSecret(ctx, dbgen.LockWebhookSecretParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	secret, _, err := codes.URLToken()
	if err != nil {
		return "", time.Time{}, err
	}
	ct, nonce, err := s.box.Seal(organizationID, "webhook-signing", id.String(), []byte(secret))
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().UTC().Add(SecretRotationOverlap)
	if err := q.RotateWebhookSecret(ctx, dbgen.RotateWebhookSecretParams{
		SecretCt: ct, SecretNonce: nonce, PreviousCt: cur.SecretCt, PreviousNonce: cur.SecretNonce,
		PreviousExpiresAt: &until, ID: id, OrganizationID: organizationID,
	}); err != nil {
		return "", time.Time{}, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "webhook.secret_rotated", "webhook_subscription", id,
		map[string]any{"previous_secret_expires_at": until})); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return secret, until, nil
}
