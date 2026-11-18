// Package social manages each organization's external identity providers
// (Google, Microsoft, Okta, …) and the identities linked through them, and runs
// the OAuth 2.0 / OIDC sign-in with them, both per organization and for the
// console's own organization-less sign-in (platform.go).
package social

import (
	"errors"
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

// Deps are what the social sign-in service is built from. All are required
// but ReturnOrigins and Platform.
type Deps struct {
	Pool   *pgxpool.Pool
	Auth   *auth.Service
	Cipher *envelope.Cipher // seals the providers' client secrets
	// Capture keeps a provider from creating or signing in an account on a
	// domain whose organization requires single sign-on.
	Capture    auth.DomainCapture
	Egress     *egress.Policy // the outbound policy providers are reached under
	AppBaseURL string         // where the console's callback is served
	// ReturnOrigins are the origins a return_to may point at. With none, only
	// root-relative paths are accepted.
	ReturnOrigins []string
	// Platform are the console's organization-less providers; none turns its
	// social sign-in off.
	Platform []PlatformProvider
}

// NewService returns the social sign-in service built from d, or an error
// naming the dependency d lacks.
func NewService(d Deps) (*Service, error) {
	switch {
	case d.Pool == nil:
		return nil, errors.New("social: missing Pool")
	case d.Auth == nil:
		return nil, errors.New("social: missing Auth")
	case d.Cipher == nil:
		return nil, errors.New("social: missing Cipher")
	case d.Capture == nil:
		return nil, errors.New("social: missing Capture")
	case d.Egress == nil:
		return nil, errors.New("social: missing Egress")
	case d.AppBaseURL == "":
		return nil, errors.New("social: missing AppBaseURL")
	}
	s := &Service{
		pool:       d.Pool,
		q:          dbgen.New(d.Pool),
		auth:       d.Auth,
		appBaseURL: strings.TrimRight(d.AppBaseURL, "/"),
		oauth:      newOAuthClient(d.Egress),
		oidc:       oidcrp.New(d.Egress),
		apple:      appleProvider,
		egress:     d.Egress,
		box:        d.Cipher,
		capture:    d.Capture,
		platform:   map[string]providerConfig{},
		returnTo:   returnto.Origins(d.ReturnOrigins...),
	}
	for _, p := range d.Platform {
		s.platform[p.name] = p.config
	}
	s.link = &provision.Flow{Pool: d.Pool, Method: "social", Weigh: s.weigh, Errors: provision.Errors{
		NotHome:            errs.ErrSocialAccountNotInOrganization,
		EmailMissing:       ErrEmailMissing,
		AccountUnverified:  ErrAccountUnverified,
		AccountAdministers: ErrAccountAdministers,
	}}
	s.link.Recorder = d.Auth
	return s, nil
}

// validateReturnTo accepts "" (no hosted flow), or a return_to returnto
// allows: the callback redirects there after setting the SSO cookie.
func (s *Service) validateReturnTo(returnTo string) error {
	if returnTo != "" && !s.returnTo.Valid(returnTo) {
		return ErrReturnToInvalid
	}
	return nil
}
