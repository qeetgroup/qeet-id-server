package user

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An account must keep at least one way to sign in: its password and passkeys
// (while its organization allows each method) and each linked identity that can
// still sign in. A removal counts and removes in one transaction holding the
// account's lock (LockSignInMethods), so two at once can't both succeed.

// SignInMethods is how many ways an account can sign in.
type SignInMethods struct {
	Password         bool `json:"password"`
	Passkeys         int  `json:"passkeys"`
	LinkedIdentities int  `json:"linked_identities"`
}

// Total is the number of ways in.
func (m SignInMethods) Total() int {
	n := m.Passkeys + m.LinkedIdentities
	if m.Password {
		n++
	}
	return n
}

// countSignInMethods counts the account's ways to sign in through db, the pool
// or a transaction.
func countSignInMethods(ctx context.Context, db dbgen.DBTX, userID uuid.UUID) (SignInMethods, error) {
	row, err := dbgen.New(db).CountSignInMethods(ctx, userID)
	return SignInMethods{Password: row.Password, Passkeys: int(row.Passkeys), LinkedIdentities: int(row.LinkedIdentities)}, err
}

// CountSignInMethods counts the account's ways to sign in, for display. A
// removal decides with LockSignInMethods instead.
func CountSignInMethods(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID) (SignInMethods, error) {
	return countSignInMethods(postgres.AcrossOrganizations(ctx), pool, userID)
}

// LockSignInMethods takes the account's lock inside tx — the one session
// revocations and password changes take — and counts its ways to sign in.
// ErrNotFound for an account that does not exist. The methods span the
// account's organizations, so tx must have begun with postgres.AcrossOrganizations.
func LockSignInMethods(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (SignInMethods, error) {
	if _, err := dbgen.New(tx).LockAccount(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SignInMethods{}, errs.ErrNotFound
		}
		return SignInMethods{}, err
	}
	return countSignInMethods(ctx, tx, userID)
}

// Remover is who asks to remove a way to sign in — the person themselves or an
// administrator — for the audit record of a refusal. An empty Type is a user.
type Remover = audit.Actor

// RefuseLastMethodRemoval records, on its own (the removal it describes was
// rolled back), that by was refused removing method (methodID) — "passkey" or
// "linked_identity" — from userID's account as its last way to sign in, and
// returns ErrAuthLastSignInMethod. A nil organizationID records it on a
// platform chain.
func RefuseLastMethodRemoval(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, organizationID *uuid.UUID, method string, methodID uuid.UUID, by audit.Actor) error {
	if err := audit.RecordAlone(ctx, pool, by.EventIn(organizationID, "auth.sign_in_method_removal_refused", "user", userID,
		map[string]any{"method": method, "method_id": methodID, "reason": "last_sign_in_method"})); err != nil {
		return err
	}
	return errs.ErrAuthLastSignInMethod
}
