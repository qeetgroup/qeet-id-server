// Package social manages each organization's external identity providers
// (Google, Microsoft, Okta, …) and the identities linked through them, and runs
// the OAuth 2.0 / OIDC sign-in with them, both per organization and for the
// console's own organization-less sign-in (platform.go).
package social

import (
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/returnto"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Service manages social providers and runs social sign-in. OpenID Connect
// providers and Apple are signed in through oidc, the other adapters through
// oauth. platform holds the console's env-configured organization-less
// providers (platform.go); returnTo is the return_to allowlist.
type Service struct {
	pool       *pgxpool.Pool
	q          *dbgen.Queries
	auth       *auth.Service
	appBaseURL string
	oauth      *oauthClient
	oidc       *oidcrp.Client
	apple      oidcrp.Discovery
	link       *provision.Flow
	egress     *egress.Policy
	box        *envelope.Cipher
	capture    auth.DomainCapture
	platform   map[string]providerConfig
	returnTo   returnto.Allowed
}

// SetDomainCapture sets the check that keeps a provider from creating an
// account on a domain whose organization requires single sign-on (nil: no
// address is captured).
func (s *Service) SetDomainCapture(c auth.DomainCapture) { s.capture = c }

// SetAllowedReturnOrigins sets the origins a return_to may point at. With none,
// only root-relative paths are accepted.
func (s *Service) SetAllowedReturnOrigins(origins ...string) {
	s.returnTo = returnto.Origins(origins...)
}

// validateReturnTo accepts "" (no hosted flow), or a return_to returnto
// allows: the callback redirects there after setting the SSO cookie.
func (s *Service) validateReturnTo(returnTo string) error {
	if returnTo != "" && !s.returnTo.Valid(returnTo) {
		return ErrReturnToInvalid
	}
	return nil
}

// SetCipher sets the cipher that encrypts social sign-in secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// NewService returns the social sign-in service.
func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	s := &Service{
		pool:       pool,
		q:          dbgen.New(pool),
		auth:       authSvc,
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
		oauth:      newOAuthClient(policy),
		oidc:       oidcrp.New(policy),
		apple:      appleProvider,
		egress:     policy,
	}
	s.link = &provision.Flow{Pool: pool, Method: "social", Weigh: s.weigh, Errors: provision.Errors{
		NotHome:            errs.ErrSocialAccountNotInOrganization,
		EmailMissing:       ErrEmailMissing,
		AccountUnverified:  ErrAccountUnverified,
		AccountAdministers: ErrAccountAdministers,
	}}
	if authSvc != nil {
		s.link.Recorder = authSvc
	}
	return s
}
