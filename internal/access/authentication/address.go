package auth

import (
	"context"

	"github.com/google/uuid"
)

// AddressPolicy is the organisation's address rules: CheckSignIn returns
// errs.ErrAuthAddressNotAllowed (having recorded the refusal) when ip may not
// sign in to tenantID, and nil when it may or the rules are off. Satisfied by
// *ipallow.Service; an interface so auth doesn't import it. Wired via
// SetAddressPolicy.
type AddressPolicy interface {
	CheckSignIn(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error
}

// SetAddressPolicy wires the address rules into every sign-in and renewal.
// Called from internal/bootstrap/dependencies.go.
func (s *Service) SetAddressPolicy(p AddressPolicy) { s.addresses = p }

// CheckSignInAddress asks tenantID's address rules whether ip may sign in to it
// (errs.ErrAuthAddressNotAllowed, recorded, when not). For a hosted-login step
// that opens no session of its own, such as the social callback. No
// organisation, or no rules wired: yes.
func (s *Service) CheckSignInAddress(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error {
	return s.checkAddress(ctx, tenantID, userID, ip, path)
}

// checkAddress asks the organisation's address rules whether ip may sign in
// to it, or renew a session in it. No organisation, or no rules wired: yes.
func (s *Service) checkAddress(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error {
	if s.addresses == nil || tenantID == uuid.Nil {
		return nil
	}
	return s.addresses.CheckSignIn(ctx, tenantID, userID, ip, path)
}
