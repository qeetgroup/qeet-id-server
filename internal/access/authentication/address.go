package auth

import (
	"context"

	"github.com/google/uuid"
)

// AddressPolicy applies an organisation's address rules. CheckSignIn returns
// errs.ErrAuthAddressNotAllowed, after recording the refusal, when ip may not
// sign in to tenantID. Satisfied by *ipallow.Service.
type AddressPolicy interface {
	CheckSignIn(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error
}

// SetAddressPolicy wires the address rules into every sign-in and renewal.
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
