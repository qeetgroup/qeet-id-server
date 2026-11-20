// Package overview answers an organization's dashboard in one read: for each
// area the caller may read, whether it is set up and how much of it there is,
// leaving out every area the caller's permissions don't cover. The detailed
// lists stay with their own pages.
package overview

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/overview/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// The permissions the areas need: the same each area's own list needs.
const (
	permConnections = "connection.read"
	permAPIKeys     = "apikey.read"
	permWebhooks    = "webhook.read"
	permPolicies    = "policy.read"
	permMembers     = "user.read"
	permBilling     = "billing.read"
)

// Authorizer reports whether p may use a route that needs permission, as the
// route guard decides it: a person by their roles (an application's token only
// within its scopes), a machine credential by its scopes.
type Authorizer func(ctx context.Context, p *httpx.Principal, permission string) (bool, error)

// SignInSettings reads an organization's sign-in settings. Satisfied by
// *authpolicy.Service.
type SignInSettings interface {
	AllowedSignInMethods(ctx context.Context, organizationID uuid.UUID) (password, passkey, magicLink bool, err error)
	SelfRegistrationEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
	RememberDeviceEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
}

// Service builds an organization's overview.
type Service struct {
	q       *dbgen.Queries
	allowed Authorizer
	signIn  SignInSettings
}

// NewService returns the Service over pool, deciding what a caller may read
// with allowed and reading sign-in settings from signIn; it refuses a missing
// one.
func NewService(pool *pgxpool.Pool, allowed Authorizer, signIn SignInSettings) (*Service, error) {
	switch {
	case allowed == nil:
		return nil, errors.New("overview: an authorizer is required")
	case signIn == nil:
		return nil, errors.New("overview: the sign-in settings are required")
	}
	return &Service{q: dbgen.New(pool), allowed: allowed, signIn: signIn}, nil
}

// Overview is an organization's dashboard. Each area is present only when the
// caller may read it, and then carries every one of its fields.
type Overview struct {
	OrganizationID    uuid.UUID          `json:"organization_id"`
	GeneratedAt       time.Time          `json:"generated_at"`
	SingleSignOn      *SingleSignOn      `json:"single_sign_on,omitempty"`
	Applications      *Applications      `json:"applications,omitempty"`
	Domains           *Domains           `json:"domains,omitempty"`
	Directory         *Directory         `json:"directory,omitempty"`
	RememberedDevices *RememberedDevices `json:"remembered_devices,omitempty"`
	APIKeys           *APIKeys           `json:"api_keys,omitempty"`
	Webhooks          *Webhooks          `json:"webhooks,omitempty"`
	SignIn            *SignIn            `json:"sign_in,omitempty"`
	AccessPolicies    *AccessPolicies    `json:"access_policies,omitempty"`
	Threats           *Threats           `json:"threats,omitempty"`
	Invitations       *Invitations       `json:"invitations,omitempty"`
	Billing           *Billing           `json:"billing,omitempty"`
}

// Count is how many there are of something, and how many are in use.
type Count struct {
	Total  int `json:"total"`
	Active int `json:"active"`
}

// SingleSignOn is how people sign in through the organization's identity
// providers: its connections by protocol, its social providers (Active: turned
// on) and its SCIM tokens still accepted.
type SingleSignOn struct {
	SAML             Count `json:"saml"`
	LDAP             Count `json:"ldap"`
	OIDC             Count `json:"oidc"`
	SocialProviders  Count `json:"social_providers"`
	SCIMTokensActive int   `json:"scim_tokens_active"`
}

// Applications are the apps the organization signs people in to: its OpenID
// Connect applications, its SAML service providers, and the live grants
// people gave the applications, with how many people hold one.
type Applications struct {
	OIDCClients          int   `json:"oidc_clients"`
	SAMLServiceProviders Count `json:"saml_service_providers"`
	ActiveGrants         int   `json:"active_grants"`
	PeopleWithGrants     int   `json:"people_with_grants"`
}

// Domains are the organization's domains: all, verified, and verified with
// single sign-on required.
type Domains struct {
	Total       int `json:"total"`
	Verified    int `json:"verified"`
	SSORequired int `json:"sso_required"`
}

// Directory is the organization's directory errors of the last 7 days still
// open.
type Directory struct {
	OpenErrors int `json:"open_errors"`
}

// RememberedDevices are the devices that still skip the second step, and the
// people they belong to.
type RememberedDevices struct {
	Devices int `json:"devices"`
	People  int `json:"people"`
}

// APIKeys are the organization's API keys still accepted.
type APIKeys struct {
	Active int `json:"active"`
}

// Webhooks are the organization's webhook subscriptions: all, turned on, and
// turned on with failing deliveries.
type Webhooks struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
	Failing int `json:"failing"`
}

// SignIn is how people sign in: the first-factor methods allowed, whether
// people may register themselves and devices be remembered, and who must use a
// second factor.
type SignIn struct {
	Password         bool   `json:"password"`
	Passkey          bool   `json:"passkey"`
	MagicLink        bool   `json:"magic_link"`
	SelfRegistration bool   `json:"self_registration"`
	RememberDevice   bool   `json:"remember_device"`
	MFAEnforcement   string `json:"mfa_enforcement"`
}

// AccessPolicies are the organization's attribute-based access policies: all,
// and turned on.
type AccessPolicies struct {
	ABAC Count `json:"abac"`
}

// Threats are the organization's security anomalies still open.
type Threats struct {
	OpenAnomalies int `json:"open_anomalies"`
}

// Invitations are the organization's invitations still waiting to be answered.
type Invitations struct {
	Pending int `json:"pending"`
}

// Billing is the organization's plan, and its subscription's state when it
// has one (null fields without).
type Billing struct {
	Plan               string     `json:"plan"`
	SubscriptionStatus *string    `json:"subscription_status"`
	TrialEnd           *time.Time `json:"trial_end"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end"`
	CancelAtPeriodEnd  bool       `json:"cancel_at_period_end"`
}

// Overview returns organizationID's overview as p may read it: each area only
// when p holds the permission its own list needs. Any failure fails the whole
// read, so the dashboard shows one error rather than a partial picture.
func (s *Service) Overview(ctx context.Context, p *httpx.Principal, organizationID uuid.UUID) (*Overview, error) {
	may := map[string]bool{}
	for _, permission := range []string{permConnections, permAPIKeys, permWebhooks, permPolicies, permMembers, permBilling} {
		ok, err := s.allowed(ctx, p, permission)
		if err != nil {
			return nil, err
		}
		may[permission] = ok
	}
	out := &Overview{OrganizationID: organizationID, GeneratedAt: time.Now().UTC()}
	for _, area := range []struct {
		permission string
		read       func(context.Context, uuid.UUID, *Overview) error
	}{
		{permConnections, s.connections},
		{permAPIKeys, s.apiKeys},
		{permWebhooks, s.webhooks},
		{permPolicies, s.policies},
		{permMembers, s.invitations},
		{permBilling, s.billing},
	} {
		if !may[area.permission] {
			continue
		}
		if err := area.read(ctx, organizationID, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// connections reads the areas connection.read covers: single sign-on,
// applications, domains, the directory and remembered devices.
func (s *Service) connections(ctx context.Context, organizationID uuid.UUID, out *Overview) error {
	sso, err := s.q.SingleSignOn(ctx, organizationID)
	if err != nil {
		return err
	}
	out.SingleSignOn = &SingleSignOn{
		SAML:             Count{int(sso.SamlTotal), int(sso.SamlActive)},
		LDAP:             Count{int(sso.LdapTotal), int(sso.LdapActive)},
		OIDC:             Count{int(sso.OidcTotal), int(sso.OidcActive)},
		SocialProviders:  Count{int(sso.SocialTotal), int(sso.SocialEnabled)},
		SCIMTokensActive: int(sso.ScimTokensActive),
	}
	apps, err := s.q.Applications(ctx, organizationID)
	if err != nil {
		return err
	}
	out.Applications = &Applications{
		OIDCClients:          int(apps.OidcClients),
		SAMLServiceProviders: Count{int(apps.SamlProvidersTotal), int(apps.SamlProvidersActive)},
		ActiveGrants:         int(apps.GrantsActive),
		PeopleWithGrants:     int(apps.GrantHolders),
	}
	domains, err := s.q.Domains(ctx, organizationID)
	if err != nil {
		return err
	}
	out.Domains = &Domains{Total: int(domains.Total), Verified: int(domains.Verified), SSORequired: int(domains.SsoRequired)}
	open, err := s.q.DirectoryErrors(ctx, organizationID)
	if err != nil {
		return err
	}
	out.Directory = &Directory{OpenErrors: int(open)}
	devices, err := s.q.RememberedDevices(ctx, organizationID)
	if err != nil {
		return err
	}
	out.RememberedDevices = &RememberedDevices{Devices: int(devices.Devices), People: int(devices.People)}
	return nil
}

func (s *Service) apiKeys(ctx context.Context, organizationID uuid.UUID, out *Overview) error {
	active, err := s.q.APIKeys(ctx, organizationID)
	if err != nil {
		return err
	}
	out.APIKeys = &APIKeys{Active: int(active)}
	return nil
}

func (s *Service) webhooks(ctx context.Context, organizationID uuid.UUID, out *Overview) error {
	w, err := s.q.Webhooks(ctx, organizationID)
	if err != nil {
		return err
	}
	out.Webhooks = &Webhooks{Total: int(w.Total), Enabled: int(w.Enabled), Failing: int(w.Failing)}
	return nil
}

// policies reads the areas policy.read covers: sign-in, access policies and
// threats.
func (s *Service) policies(ctx context.Context, organizationID uuid.UUID, out *Overview) error {
	in := SignIn{}
	var err error
	if in.Password, in.Passkey, in.MagicLink, err = s.signIn.AllowedSignInMethods(ctx, organizationID); err != nil {
		return err
	}
	if in.SelfRegistration, err = s.signIn.SelfRegistrationEnabled(ctx, organizationID); err != nil {
		return err
	}
	if in.RememberDevice, err = s.signIn.RememberDeviceEnabled(ctx, organizationID); err != nil {
		return err
	}
	if in.MFAEnforcement, err = s.q.MFAEnforcement(ctx, organizationID); err != nil {
		return err
	}
	out.SignIn = &in
	policies, err := s.q.AccessPolicies(ctx, organizationID)
	if err != nil {
		return err
	}
	out.AccessPolicies = &AccessPolicies{ABAC: Count{int(policies.AbacTotal), int(policies.AbacEnabled)}}
	out.Threats = &Threats{OpenAnomalies: int(policies.OpenAnomalies)}
	return nil
}

func (s *Service) invitations(ctx context.Context, organizationID uuid.UUID, out *Overview) error {
	pending, err := s.q.PendingInvitations(ctx, organizationID)
	if err != nil {
		return err
	}
	out.Invitations = &Invitations{Pending: int(pending)}
	return nil
}

func (s *Service) billing(ctx context.Context, organizationID uuid.UUID, out *Overview) error {
	b, err := s.q.Billing(ctx, organizationID)
	if err != nil {
		return err
	}
	out.Billing = &Billing{Plan: b.Plan, SubscriptionStatus: b.SubscriptionStatus, TrialEnd: b.TrialEnd,
		CurrentPeriodEnd: b.CurrentPeriodEnd, CancelAtPeriodEnd: b.CancelAtPeriodEnd}
	return nil
}
