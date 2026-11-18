// Package authhook runs an organization's synchronous sign-in hooks: after the
// credentials check, Run POSTs a signed event to each enabled hook's URL, which
// answers allow or deny. When a hook gives no answer, its fail_open decides
// (allow by default, so an outage never locks everyone out) and the skip is
// recorded.
package authhook

import (
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/authhook/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Hook is an organization's login hook, without its signing secret. LastOutcome is
// how its last sign-in call ended: allowed, denied or skipped (no answer).
// PreviousSecretExpiresAt is when a replaced secret stops signing its calls
// beside the new one (nil: none does).
type Hook struct {
	ID                      uuid.UUID  `json:"id"`
	Trigger                 string     `json:"trigger"`
	URL                     string     `json:"url"`
	Enabled                 bool       `json:"enabled"`
	FailOpen                bool       `json:"fail_open"`
	CreatedAt               time.Time  `json:"created_at"`
	LastCalledAt            *time.Time `json:"last_called_at"`
	LastOutcome             *string    `json:"last_outcome"`
	LastStatusCode          *int       `json:"last_status_code"`
	Calls                   int64      `json:"calls"`
	Skips                   int64      `json:"skips"`
	Denies                  int64      `json:"denies"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at"`
}

// Service manages and runs sign-in hooks. known holds each organization's hooks
// as last read (uuid.UUID → hookState), for a sign-in made while they can't be
// read.
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
