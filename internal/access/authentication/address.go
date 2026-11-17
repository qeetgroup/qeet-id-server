package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AddressPolicy applies an organization's address rules. CheckSignIn returns
// errs.ErrAuthAddressNotAllowed, after recording the refusal, when ip may not
// sign in to organizationID; CheckSignInTx does so through tx, recording the refusal
// there for the caller to commit. Satisfied by *ipallow.Service.
type AddressPolicy interface {
	CheckSignIn(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error
	CheckSignInTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, ip, path string) error
}

// SetAddressPolicy wires the address rules into every sign-in and renewal.
func (s *Service) SetAddressPolicy(p AddressPolicy) { s.addresses = p }

// CheckSignInAddress asks organizationID's address rules whether ip may sign in to it
// (errs.ErrAuthAddressNotAllowed, recorded, when not). For a hosted-login step
// that opens no session of its own, such as the social callback. No
// organization, or no rules wired: yes.
func (s *Service) CheckSignInAddress(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error {
	return s.checkAddress(ctx, organizationID, userID, ip, path)
}

// checkAddress asks the organization's address rules whether ip may sign in
// to it, or renew a session in it. No organization, or no rules wired: yes.
func (s *Service) checkAddress(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error {
	if s.addresses == nil || organizationID == uuid.Nil {
		return nil
	}
	return s.addresses.CheckSignIn(ctx, organizationID, userID, ip, path)
}

// checkAddressTx is checkAddress inside tx. A refusal is recorded in tx, which
// the caller commits to keep the record.
func (s *Service) checkAddressTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, ip, path string) error {
	if s.addresses == nil || organizationID == uuid.Nil {
		return nil
	}
	return s.addresses.CheckSignInTx(ctx, tx, organizationID, userID, ip, path)
}
