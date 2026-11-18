// Package webhook lets organizations subscribe to the events in its catalogue and
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
// the members who manage the organization's webhooks are alerted.
package webhook

import (
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

// Service manages the webhook subscriptions.
type Service struct {
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
func (s *Service) SetPlanGate(g entitlements.PlanGate) { s.gate = g }

// SetCipher sets the cipher that encrypts webhook secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetNotifier sets who is alerted when a failing subscription is disabled;
// nil alerts no one.
func (s *Service) SetNotifier(n notification.Notifier) { s.notifier = n }
