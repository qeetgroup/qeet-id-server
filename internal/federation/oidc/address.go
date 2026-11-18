package oidc

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
)

// SetAddressPolicy sets the address rules checked when a person signs in to an
// application: authorization codes, device approval and device token collection.
// Code redemption and refresh aren't checked, because they come from the
// application's server rather than the person.
func (s *Service) SetAddressPolicy(p ipallow.AddressPolicy) { s.addresses = p }

// checkAddress asks the organization's address rules whether ip may sign in to
// it (no rules wired: yes).
func (s *Service) checkAddress(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error {
	if s.addresses == nil {
		return nil
	}
	return s.addresses.CheckSignIn(ctx, organizationID, userID, ip, path)
}

// checkAddressTx is checkAddress inside tx. A refusal is recorded in tx, which
// the caller commits to keep the record.
func (s *Service) checkAddressTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, ip, path string) error {
	if s.addresses == nil {
		return nil
	}
	return s.addresses.CheckSignInTx(ctx, tx, organizationID, userID, ip, path)
}
