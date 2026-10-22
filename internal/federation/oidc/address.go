package oidc

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

// SetAddressPolicy sets the address rules checked when a person signs in to an
// application: authorization codes, device approval and device token collection.
// Code redemption and refresh aren't checked, because they come from the
// application's server rather than the person.
func (s *Service) SetAddressPolicy(p AddressPolicy) { s.addresses = p }

// checkAddress asks the organisation's address rules whether ip may sign in to
// it (no rules wired: yes).
func (s *Service) checkAddress(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error {
	if s.addresses == nil {
		return nil
	}
	return s.addresses.CheckSignIn(ctx, tenantID, userID, ip, path)
}
