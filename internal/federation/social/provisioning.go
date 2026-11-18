package social

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// findOrCreateUser is signInAccount for a sign-in with no browser to name.
func (s *Service) findOrCreateUser(ctx context.Context, organizationID uuid.UUID, provider string, ui userInfo) (uuid.UUID, error) {
	return s.signInAccount(ctx, organizationID, provider, ui, audit.Actor{Type: "social"})
}

// signInAccount returns the account organizationID's provider signs in for ui,
// found, adopted or created by identitylink's rules as weigh weighs the
// provider's word, recording a refusal as actor's.
func (s *Service) signInAccount(ctx context.Context, organizationID uuid.UUID, provider string, ui userInfo, actor audit.Actor) (uuid.UUID, error) {
	verified := ui.EmailVerified
	return s.link.Resolve(ctx, provision.Source{OrganizationID: organizationID, Provider: provider},
		provision.Person{Subject: ui.Subject, Email: ui.Email, EmailVerified: &verified, Name: ui.Name}, actor)
}

// weigh weighs the address p asserts for src's provider (identitylink's
// Flow.Weigh). Adopting an account needs an address the provider proves, off
// a domain that requires single sign-on. Creating one is self-registration,
// so it follows the organization's setting exactly as password and passkey
// sign-up do, and is refused on a domain that requires single sign-on or
// another organization manages; an address the provider doesn't prove may
// name a new account, never marked verified.
func (s *Service) weigh(ctx context.Context, src provision.Source, p provision.Person) (provision.Vouching, error) {
	registration := s.requireSelfRegistration(ctx, src.OrganizationID)
	vouch, err := s.vouchingFor(ctx, src.OrganizationID, src.Provider, p.Email, p.EmailVerified != nil && *p.EmailVerified)
	if err != nil {
		return provision.Vouching{}, err
	}
	v := provision.Vouching{Create: registration}
	if v.Create == nil {
		v.Create = vouch.refusal
	}
	if !vouch.proved {
		v.Unproved = ErrEmailUnverified
	}
	if errors.Is(vouch.refusal, errs.ErrAuthSSORequired) {
		v.Adopt = vouch.refusal
	}
	return v, nil
}

// refuseCapturedAccount returns errs.ErrAuthSSORequired when userID's address
// is on a domain whose organization requires single sign-on and the account
// isn't exempt: social sign-in, whichever provider, never satisfies it.
func (s *Service) refuseCapturedAccount(ctx context.Context, userID uuid.UUID) error {
	if s.capture == nil {
		return nil
	}
	email, err := s.q.AccountEmail(ctx, userID)
	if err != nil {
		return err
	}
	return s.capture.RefuseCaptured(ctx, email)
}

// vouching is what a provider's word for an address is worth to an organization:
// proved reports whether it verifies the address, and refusal, when set, is
// why the provider may not create an account for it.
type vouching struct {
	proved  bool
	refusal error
}

// vouchingFor weighs email, which the provider says it verified when
// verified, for organizationID's provider. An OpenID Connect provider's
// endpoints are the organization's choice, so it proves only addresses on
// domains the organization manages; an adapter's are fixed. It reads every
// organization's domains, so it runs before the transaction.
func (s *Service) vouchingFor(ctx context.Context, organizationID uuid.UUID, provider, email string, verified bool) (vouching, error) {
	v := vouching{proved: verified}
	domain, managed, err := domainverify.ManagingDomain(postgres.AcrossOrganizations(ctx), s.pool, email)
	if err != nil {
		return v, err
	}
	own := managed && domain.OrganizationID == organizationID
	if adapterKind(provider) == kindOIDC && !own {
		v.proved = false
	}
	if !managed {
		return v, nil
	}
	// A domain that requires single sign-on takes new accounts through it
	// alone, and any other managed domain only from its own organization.
	if domain.SSO && s.capture != nil {
		err := s.capture.RefuseCaptured(ctx, email)
		if errors.Is(err, errs.ErrAuthSSORequired) {
			v.refusal = err
			return v, nil
		}
		if err != nil {
			return v, err
		}
	}
	if !own {
		v.refusal = errs.ErrUserDomainManaged
	}
	return v, nil
}

// requireSelfRegistration refuses with ErrAuthSelfRegistrationDisabled unless
// the organization allows self-registration. No wired policy counts as closed.
func (s *Service) requireSelfRegistration(ctx context.Context, organizationID uuid.UUID) error {
	if s.auth == nil {
		return errs.ErrAuthSelfRegistrationDisabled
	}
	open, err := s.auth.SelfRegistrationEnabled(ctx, organizationID)
	if err != nil {
		return err
	}
	if !open {
		return errs.ErrAuthSelfRegistrationDisabled
	}
	return nil
}

// recordSignUpRefused audits a social sign-up refused because the organization does
// not allow self-registration, naming the provider and the asserted address so
// an administrator can see who tried to join. Written on its own: the
// provisioning transaction it describes was rolled back.
func (s *Service) recordSignUpRefused(ctx context.Context, organizationID uuid.UUID, provider string, ui userInfo) error {
	return audit.RecordAlone(ctx, s.pool, audit.Actor{Type: "system"}.Event(organizationID, "social.signup_refused", "organization", organizationID, map[string]any{
		"provider":       provider,
		"email":          ui.Email,
		"email_verified": ui.EmailVerified,
		"reason":         "self_registration_disabled",
	}))
}
