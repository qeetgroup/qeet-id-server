// Package siem streams an organization's audit events to an external collector: Splunk
// HEC, Datadog logs or a generic HTTP endpoint. A sink streams from when it was
// created, with no backfill, and delivery is at-least-once: its cursor advances
// only after a 2xx.
package siem

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/siem/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	typeSplunkHEC = "splunk_hec"
	typeDatadog   = "datadog"
	typeHTTP      = "http"
)

// Sink is an organization's configured log destination. Its token is stored encrypted
// and never returned.
type Sink struct {
	ID              uuid.UUID  `json:"id"`
	Type            string     `json:"type"`
	Endpoint        string     `json:"endpoint"`
	Enabled         bool       `json:"enabled"`
	LastForwardedAt *time.Time `json:"last_forwarded_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// AuditEvent is the forwarded form of an audit row.
type AuditEvent struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	Action         string          `json:"action"`
	ActorType      string          `json:"actor_type"`
	ActorUserID    *string         `json:"actor_user_id,omitempty"`
	ResourceType   string          `json:"resource_type,omitempty"`
	ResourceID     *string         `json:"resource_id,omitempty"`
	IP             *string         `json:"ip,omitempty"`
	UserAgent      string          `json:"user_agent,omitempty"`
	RequestID      string          `json:"request_id,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// Service manages organizations' log sinks and forwards audit events to them. Sink
// tokens are sealed with the cipher from SetCipher; without one, no sink can be
// created.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	client *http.Client
	egress *egress.Policy
	box    *envelope.Cipher
}

// SetCipher sets the cipher that encrypts sink tokens.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// NewService returns a Service whose HTTP client follows policies[0], or by
// default may reach only public https endpoints.
func NewService(pool *pgxpool.Pool, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{
		pool:   pool,
		q:      dbgen.New(pool),
		client: policy.HTTPClient(10 * time.Second),
		egress: policy,
	}
}

func validType(t string) bool {
	return t == typeSplunkHEC || t == typeDatadog || t == typeHTTP
}
