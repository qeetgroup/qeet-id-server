// Package tokenvault stores each organization's third-party OAuth tokens (Slack,
// GitHub, Google, or any registered OAuth2 provider), encrypted. A user connects
// once through an authorization-code flow; GetAccessToken then returns a live
// access token, never the refresh token.
package tokenvault

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const connectStateTTL = 10 * time.Minute

// expirySkew treats a token as due for refresh slightly before it actually
// expires, so a slow caller never hands out a token that dies mid-flight.
const expirySkew = 60 * time.Second

// Provider is an organization's registered OAuth2 endpoint config for one
// third-party service. ClientSecret is never returned by the API.
type Provider struct {
	ID           uuid.UUID `json:"id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	AuthorizeURL string    `json:"authorize_url"`
	TokenURL     string    `json:"token_url"`
	Scopes       string    `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// GrantMeta is the non-secret view of a connected account.
type GrantMeta struct {
	Provider          string     `json:"provider"`
	ExternalAccountID *string    `json:"external_account_id,omitempty"`
	Scope             *string    `json:"scope,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// Service stores each organization's OAuth provider settings and its users'
// third-party tokens, encrypted at rest.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	box    *envelope.Cipher
	http   *http.Client
	egress *egress.Policy
}

// NewService builds the vault, sealing tokens with box — the same cipher the
// secrets vault uses, so both are keyed off one KMS/static-key setup.
func NewService(pool *pgxpool.Pool, box *envelope.Cipher, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{pool: pool, q: dbgen.New(pool), box: box, http: policy.HTTPClient(10 * time.Second), egress: policy}
}

func (s *Service) encrypt(organizationID, userID uuid.UUID, provider, purpose, plaintext string) (ciphertext, nonce []byte, err error) {
	resource := userID.String() + ":" + provider
	return s.box.Seal(organizationID, purpose, resource, []byte(plaintext))
}

func (s *Service) decrypt(organizationID, userID uuid.UUID, provider, purpose string, ciphertext, nonce []byte) (string, error) {
	resource := userID.String() + ":" + provider
	pt, err := s.box.Open(organizationID, purpose, resource, ciphertext, nonce)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
