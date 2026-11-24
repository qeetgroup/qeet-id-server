package oidc

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// checkAddress asks the organization's address rules whether ip may sign in to
// it.
func (s *Service) checkAddress(ctx context.Context, organizationID, userID uuid.UUID, ip, path string) error {
	return s.addresses.CheckSignIn(ctx, organizationID, userID, ip, path)
}

// checkAddressTx is checkAddress inside tx. A refusal is recorded in tx, which
// the caller commits to keep the record.
func (s *Service) checkAddressTx(ctx context.Context, tx pgx.Tx, organizationID, userID uuid.UUID, ip, path string) error {
	return s.addresses.CheckSignInTx(ctx, tx, organizationID, userID, ip, path)
}
