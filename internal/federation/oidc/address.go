package oidc

import (
	"context"

	"github.com/google/uuid"
)

// AddressPolicy is the organisation's address rules: CheckSignIn returns
// errs.ErrAuthAddressNotAllowed (having recorded the refusal) when ip may not
// sign in to tenantID, and nil when it may or the rules are off. Satisfied by
// *ipallow.Service; an interface so oidc doesn't import it. Wired via
// SetAddressPolicy.
type AddressPolicy interface {
	CheckSignIn(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error
}

// SetAddressPolicy wires the address rules into the steps where a person signs
// in to an application: the authorization code, the device approval and the
// device's collection of its tokens. Called from
// internal/bootstrap/dependencies.go.
//
// The token endpoint's code redemption and refresh are not asked: they come
// from the application's own server, whose address says nothing about where
// the person is.
func (s *Service) SetAddressPolicy(p AddressPolicy) { s.addresses = p }

// checkAddress asks the organisation's address rules whether ip may sign in to
// it (no rules wired: yes).
func (s *Service) checkAddress(ctx context.Context, tenantID, userID uuid.UUID, ip, path string) error {
	if s.addresses == nil {
		return nil
	}
	return s.addresses.CheckSignIn(ctx, tenantID, userID, ip, path)
}
