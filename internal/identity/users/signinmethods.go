package user

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An account must keep at least one way to sign in: its password and passkeys
// (while its organisation allows each method) and each linked identity that can
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

// querier is satisfied by both a pool and a transaction.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func countSignInMethods(ctx context.Context, q querier, userID uuid.UUID) (SignInMethods, error) {
	var m SignInMethods
	// A password or passkey counts only while the account's organisation
	// allows signing in with it (no organisation: always).
	err := q.QueryRow(ctx, `
		WITH allowed AS (
		    SELECT COALESCE(ap.password_enabled, TRUE) AS password,
		           COALESCE(ap.passkey_enabled, TRUE) AS passkey
		    FROM "user".users u
		    LEFT JOIN tenant.auth_policy ap ON ap.tenant_id = u.tenant_id
		    WHERE u.id = $1
		)
		SELECT EXISTS (SELECT 1 FROM auth.password_credentials WHERE user_id = $1)
		           AND COALESCE((SELECT password FROM allowed), TRUE),
		       CASE WHEN COALESCE((SELECT passkey FROM allowed), TRUE)
		            THEN (SELECT count(*) FROM auth.passkey_credentials WHERE user_id = $1)
		            ELSE 0 END::int,
		       ((SELECT count(*) FROM "user".external_identities ei
		         WHERE ei.user_id = $1
		           AND (ei.provider IN ('saml', 'ldap') OR EXISTS (
		                SELECT 1 FROM tenant.social_providers sp
		                WHERE sp.tenant_id = ei.tenant_id AND sp.provider = ei.provider AND sp.enabled)))
		        + (SELECT count(*) FROM auth.platform_social_identities WHERE user_id = $1))::int`,
		userID).Scan(&m.Password, &m.Passkeys, &m.LinkedIdentities)
	return m, err
}

// CountSignInMethods counts the account's ways to sign in, for display. A
// removal decides with LockSignInMethods instead.
func CountSignInMethods(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID) (SignInMethods, error) {
	return countSignInMethods(postgres.AcrossTenants(ctx), pool, userID)
}

// LockSignInMethods takes the account's lock inside tx — the one session
// revocations and password changes take — and counts its ways to sign in.
// ErrNotFound for an account that does not exist. The methods span the
// account's organisations, so tx must have begun with postgres.AcrossTenants.
func LockSignInMethods(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (SignInMethods, error) {
	if err := tx.QueryRow(ctx, `SELECT id FROM "user".users WHERE id = $1 FOR NO KEY UPDATE`, userID).Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SignInMethods{}, errs.ErrNotFound
		}
		return SignInMethods{}, err
	}
	return countSignInMethods(ctx, tx, userID)
}

// Remover is who asks to remove a way to sign in — the person themselves or an
// administrator — for the audit record of a refusal.
type Remover struct {
	UserID    *uuid.UUID
	IP        string
	UserAgent string
	RequestID string
}

// RefuseLastMethodRemoval records, on its own (the removal it describes was
// rolled back), that by was refused removing method (methodID) — "passkey" or
// "linked_identity" — from userID's account as its last way to sign in, and
// returns ErrAuthLastSignInMethod.
func RefuseLastMethodRemoval(ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, tenantID *uuid.UUID, method string, methodID uuid.UUID, by Remover) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	uid := userID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  by.UserID,
		ActorType:    "user",
		Action:       "auth.sign_in_method_removal_refused",
		ResourceType: "user",
		ResourceID:   &uid,
		IP:           by.IP,
		UserAgent:    by.UserAgent,
		RequestID:    by.RequestID,
		Metadata:     map[string]any{"method": method, "method_id": methodID, "reason": "last_sign_in_method"},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return errs.ErrAuthLastSignInMethod
}
