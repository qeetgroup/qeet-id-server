package authentication

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// DomainCapture decides whether an address must sign in through its organization's identity provider:
// RefuseCaptured returns errs.ErrAuthSSORequired for an address on a captured domain that isn't a
// break-glass member, without revealing whether the address has an account. Satisfied by
// *domainverify.Service.
type DomainCapture interface {
	RefuseCaptured(ctx context.Context, email string) error
}

// refuseCaptured refuses the address's own sign-in methods when its domain
// is captured.
func (s *Service) refuseCaptured(ctx context.Context, email string) error {
	return s.capture.RefuseCaptured(ctx, email)
}

// refuseSwitchIntoCapture refuses switching userID into organizationID when organizationID
// requires single sign-on on the account's domain: its identity provider signs
// its people in there directly, so no other session is switched into it.
func (s *Service) refuseSwitchIntoCapture(ctx context.Context, userID, organizationID uuid.UUID) error {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return err
	}
	managed, ok, err := domainverify.ManagingDomain(postgres.AcrossOrganizations(ctx), s.pool, u.Email)
	if err != nil || !ok || managed.OrganizationID != organizationID {
		return err
	}
	return s.capture.RefuseCaptured(ctx, u.Email)
}
