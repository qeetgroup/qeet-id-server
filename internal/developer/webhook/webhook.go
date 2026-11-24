// Package webhook delivers an organization's subscribed events as signed POSTs of an Event, stored
// before sending so retries survive restarts. X-Qeet-Signature is "sha256=" and the hex HMAC-SHA256,
// keyed by the subscription's secret, of X-Qeet-Timestamp, "." and the body (both values while a
// rotated secret overlaps). A subscription failing for autoDisableAfter is disabled, managers alerted.
package webhook

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Service manages the webhook subscriptions and sends their deliveries; its
// Queue queues them.
type Service struct {
	*Queue
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	client   *http.Client
	gate     entitlements.PlanGate
	notifier notification.Notifier
	egress   *egress.Policy
	box      *envelope.Cipher
	workerID uuid.UUID
	lease    time.Duration
}

// Deps are what a Service is built from besides its pool. Cipher, PlanGate
// and Notifier are required; a nil Egress lets deliveries reach only public
// https endpoints.
type Deps struct {
	Cipher   *envelope.Cipher      // seals subscription secrets
	PlanGate entitlements.PlanGate // webhooks are a plan feature
	Notifier notification.Notifier // alerts managers when a failing subscription is turned off
	Egress   *egress.Policy        // where deliveries may go
}

// NewService returns the webhook service, refusing a missing dependency.
func NewService(pool *pgxpool.Pool, d Deps) (*Service, error) {
	switch {
	case d.Cipher == nil:
		return nil, errors.New("webhook: a cipher is required to seal subscription secrets")
	case d.PlanGate == nil:
		return nil, errors.New("webhook: a plan gate is required, as webhooks are a plan feature")
	case d.Notifier == nil:
		return nil, errors.New("webhook: a notifier is required to alert managers of a disabled subscription")
	}
	var policies []*egress.Policy
	if d.Egress != nil {
		policies = append(policies, d.Egress)
	}
	policy := egress.PublicPolicy(policies...)
	return &Service{
		Queue:    NewQueue(pool),
		pool:     pool,
		q:        dbgen.New(pool),
		client:   policy.HTTPClient(10 * time.Second),
		gate:     d.PlanGate,
		notifier: d.Notifier,
		egress:   policy,
		box:      d.Cipher,
		workerID: uuid.New(),
		lease:    2 * time.Minute,
	}, nil
}
