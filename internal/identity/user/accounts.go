package user

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// accounts makes an administrator's changes to accounts. Each change owns its
// transaction, in which its audit rows, events and ended sign-ins commit with
// it or not at all.
type accounts struct {
	repo    *Repository
	signIns signInEnder
	signals *sessionsignal.Signaller
	mfa     mfaResetter
	roles   RoleGranter
}

// accounts returns the changes h's routes make, with h's collaborators.
func (h *Handler) accounts() accounts {
	return accounts{repo: h.Repo, signIns: h.SignIns, signals: h.Signals, mfa: h.MFA, roles: h.Roles}
}

// inTx runs change in a transaction of its own and commits it when change
// succeeds.
func (a accounts) inTx(ctx context.Context, change func(tx pgx.Tx) error) error {
	tx, err := a.repo.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := change(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recordAccountChange records, in tx, action on userID's account in
// organizationID by actor: its audit row and its user.events event.
func recordAccountChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, userID uuid.UUID, action string) error {
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "user", userID, nil)); err != nil {
		return err
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: userID, Topic: "user.events", EventType: action,
		Payload: map[string]any{"organization_id": organizationID, "user_id": userID}})
}

// withAudit runs change and its audit row, action on target in organizationID
// as actor, in one transaction: neither commits without the other.
func (a accounts) withAudit(ctx context.Context, actor audit.Actor, organizationID, target uuid.UUID, action string, metadata map[string]any, change func(ctx context.Context, tx pgx.Tx) error) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		if err := change(ctx, tx); err != nil {
			return err
		}
		return audit.Record(ctx, tx, actor.Event(organizationID, action, "user", target, metadata))
	})
}

// restore brings back userID's soft-deleted account, recorded as user.restored.
func (a accounts) restore(ctx context.Context, organizationID, userID uuid.UUID, actor audit.Actor) error {
	return a.withAudit(ctx, actor, organizationID, userID, "user.restored", nil, func(ctx context.Context, tx pgx.Tx) error {
		return a.repo.RestoreTx(ctx, tx, userID)
	})
}

// purge removes userID's soft-deleted account for good, recorded as user.purged.
func (a accounts) purge(ctx context.Context, organizationID, userID uuid.UUID, actor audit.Actor) error {
	return a.withAudit(ctx, actor, organizationID, userID, "user.purged", nil, func(ctx context.Context, tx pgx.Tx) error {
		return a.repo.PurgeTx(ctx, tx, userID)
	})
}

// setMfaRequired sets whether userID must use a second factor, recorded with
// the value set.
func (a accounts) setMfaRequired(ctx context.Context, organizationID, userID uuid.UUID, required bool, actor audit.Actor) error {
	return a.withAudit(ctx, actor, organizationID, userID, "user.mfa_required_set", map[string]any{"mfa_required": required},
		func(ctx context.Context, tx pgx.Tx) error { return a.repo.SetMfaRequiredTx(ctx, tx, userID, required) })
}

// create makes the account in (with its password hash, if any) as actor's,
// recorded as user.created with its event, and, with role, gives it that role
// within the seats role allows. An address on a domain another organization
// manages is refused before anything is written.
func (a accounts) create(ctx context.Context, in CreateInput, passwordHash string, role *importRole, actor audit.Actor) (*User, error) {
	if err := domainverify.CheckNewAccount(ctx, a.repo.pool, in.OrganizationID, in.Email); err != nil {
		return nil, err
	}
	var u *User
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		if u, err = a.repo.CreateWithCredentialTx(ctx, tx, in, passwordHash); err != nil {
			return err
		}
		if err := audit.Record(ctx, tx, actor.Event(u.OrganizationID, "user.created", "user", u.ID, map[string]any{"email": u.Email})); err != nil {
			return err
		}
		if err := outbox.Enqueue(ctx, tx, outbox.Event{
			AggregateID: u.ID,
			Topic:       "user.events",
			EventType:   "user.created",
			Payload:     map[string]any{"user_id": u.ID, "organization_id": u.OrganizationID, "email": u.Email, "source": "admin"},
		}); err != nil {
			return err
		}
		if role == nil {
			return nil
		}
		if err := a.roles.Assign(ctx, tx, u.ID, u.OrganizationID, role.ID, actor.UserID, role.Seats); err != nil {
			return err
		}
		return audit.Record(ctx, tx, actor.Event(u.OrganizationID, "role.assigned", "user", u.ID,
			map[string]any{"role_id": role.ID, "source": "bulk_import"}))
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// recordBulkImport records the summary of a bulk import into organizationID,
// its audit row and event.
func (a accounts) recordBulkImport(ctx context.Context, organizationID uuid.UUID, res BulkImportResult, actor audit.Actor) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		if err := audit.Record(ctx, tx, actor.Event(organizationID, "user.bulk_imported", "organization", organizationID,
			map[string]any{"succeeded": res.Succeeded, "failed": res.Failed})); err != nil {
			return err
		}
		return outbox.Enqueue(ctx, tx, outbox.Event{
			AggregateID: organizationID,
			Topic:       "user.events",
			EventType:   "user.bulk_imported",
			Payload:     map[string]any{"organization_id": organizationID, "succeeded": res.Succeeded, "failed": res.Failed},
		})
	})
}

// softDelete soft-deletes userID (recording actor as who did it), ends every
// way they are signed in, withdraws what they issued in organizationID, and
// records user.deleted. Restoring the account brings no session back.
func (a accounts) softDelete(ctx context.Context, organizationID, userID uuid.UUID, actor audit.Actor) (*Deletion, error) {
	var d *Deletion
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		if d, err = a.repo.SoftDeleteByTx(ctx, tx, userID, actor.UserID); err != nil {
			return err
		}
		if err := a.endEverySignIn(ctx, tx, userID, sessionsignal.ReasonDeleted); err != nil {
			return err
		}
		if err := recordAccountChange(ctx, tx, actor, organizationID, userID, "user.deleted"); err != nil {
			return err
		}
		return a.repo.OffboardTx(ctx, tx, organizationID, userID, actor)
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Removal is what removing a member from an organization took away.
type Removal struct {
	ID            uuid.UUID `json:"id"`
	RolesRemoved  int64     `json:"roles_removed"`
	SessionsEnded int       `json:"sessions_ended"`
}

// removeMembership takes userID out of organizationID: their roles, groups,
// sessions, application grants and API keys there, and what they issued
// there, recorded as user.removed_from_organization.
func (a accounts) removeMembership(ctx context.Context, organizationID, userID uuid.UUID, actor audit.Actor) (*Removal, error) {
	var out *Removal
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		roles, err := a.repo.RemoveFromOrganizationTx(ctx, tx, userID, organizationID)
		if err != nil {
			return err
		}
		ended, err := sessionsignal.EndUserSessionsInOrganization(ctx, tx, userID, organizationID)
		if err != nil {
			return err
		}
		a.signals.Revoked(ctx, tx, sessionsignal.ReasonRemovedFromOrganization, ended...)
		if err := recordAccountChange(ctx, tx, actor, organizationID, userID, "user.removed_from_organization"); err != nil {
			return err
		}
		if err := a.repo.OffboardTx(ctx, tx, organizationID, userID, actor); err != nil {
			return err
		}
		out = &Removal{ID: userID, RolesRemoved: roles, SessionsEnded: len(ended)}
		return nil
	})
	return out, err
}

// resetMFA clears userID's second factors, recorded as mfa.admin_reset with
// how many of each it removed.
func (a accounts) resetMFA(ctx context.Context, organizationID, userID uuid.UUID, actor audit.Actor) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		removed, err := a.mfa.ResetForUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, actor.Event(organizationID, "mfa.admin_reset", "user", userID, map[string]any{"removed": removed}))
	})
}

// setPassword ends every way userID is signed in, as revokeAllSessions does,
// sets their password hash, and records user.password_set with its event. An
// administrator's reset is usually incident response, so no session,
// application grant or trusted device survives.
func (a accounts) setPassword(ctx context.Context, organizationID, userID uuid.UUID, hash string, actor audit.Actor) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		// Unlike the self-service change there is no session to keep: the
		// caller is a different person from the account holder.
		ended, err := a.signIns.EndAllSignIns(ctx, tx, userID, sessionsignal.ReasonAdminPasswordSet)
		if err != nil {
			return err
		}
		if err := a.repo.q.WithTx(tx).SetPassword(ctx, dbgen.SetPasswordParams{UserID: userID, PasswordHash: hash}); err != nil {
			return err
		}
		if err := audit.Record(ctx, tx, actor.Event(organizationID, "user.password_set", "user", userID, map[string]any{
			"sessions_revoked":             true,
			"revoked_sessions":             ended.Sessions,
			"revoked_login_sessions":       ended.LoginSessions,
			"revoked_app_grants":           ended.AppGrants,
			"revoked_trusted_devices":      ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
		})); err != nil {
			return err
		}
		return outbox.Enqueue(ctx, tx, outbox.Event{
			AggregateID: userID,
			Topic:       "user.events",
			EventType:   "user.password_set",
			Payload:     map[string]any{"user_id": userID, "organization_id": organizationID, "sessions_revoked": true},
		})
	})
}

// revokeAllSessions ends every way userID is signed in, recorded as
// session.admin_revoked_all with a count per kind.
func (a accounts) revokeAllSessions(ctx context.Context, organizationID, userID uuid.UUID, actor audit.Actor) (SignInsEnded, error) {
	var ended SignInsEnded
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		if ended, err = a.signIns.EndAllSignIns(ctx, tx, userID, sessionsignal.ReasonAdminRevokedAll); err != nil {
			return err
		}
		return audit.Record(ctx, tx, actor.Event(organizationID, "session.admin_revoked_all", "user", userID, map[string]any{
			"revoked_sessions":             ended.Sessions,
			"revoked_login_sessions":       ended.LoginSessions,
			"revoked_app_grants":           ended.AppGrants,
			"revoked_trusted_devices":      ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
		}))
	})
	return ended, err
}

// endSession ends sessionID, one of userID's sessions in organizationID,
// recorded as session.admin_revoked and announced. ErrNotFound for any other.
func (a accounts) endSession(ctx context.Context, organizationID, userID, sessionID uuid.UUID, actor audit.Actor) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		sessionOrganization, err := a.repo.q.WithTx(tx).EndMemberSession(ctx, dbgen.EndMemberSessionParams{ID: sessionID, UserID: userID, OrganizationID: organizationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := audit.Record(ctx, tx, actor.Event(organizationID, "session.admin_revoked", "user", userID,
			map[string]any{"session_id": sessionID})); err != nil {
			return err
		}
		a.signals.Revoked(ctx, tx, sessionsignal.ReasonAdminRevoked, sessionsignal.Session{ID: sessionID, UserID: userID, OrganizationID: sessionOrganization})
		return nil
	})
}

// removePasskey removes passkeyID from userID's account, recorded as
// passkey.admin_deleted, and returns its name. The account's last way to sign
// in isn't removed: that refusal is recorded on its own.
func (a accounts) removePasskey(ctx context.Context, organizationID, userID, passkeyID uuid.UUID, actor audit.Actor) (string, error) {
	// The account's other ways to sign in span its organizations.
	ctx = postgres.AcrossOrganizations(ctx)
	tx, err := a.repo.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	methods, err := LockSignInMethods(ctx, tx, userID)
	if err != nil {
		return "", err
	}
	name, err := a.repo.q.WithTx(tx).DeleteUserPasskey(ctx, dbgen.DeleteUserPasskeyParams{ID: passkeyID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		return "", RefuseLastMethodRemoval(ctx, a.repo.pool, userID, &organizationID, "passkey", passkeyID, actor)
	}
	passkeyName := ""
	if name != nil {
		passkeyName = *name
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "passkey.admin_deleted", "user", userID,
		map[string]any{"passkey_id": passkeyID, "name": passkeyName})); err != nil {
		return "", err
	}
	return passkeyName, tx.Commit(ctx)
}

// update applies an administrator's update to userID, an account of
// organizationID, with its evidence: user.updated naming the profile fields it
// changed, and a status change's own record, event and ended sign-ins.
// Nobody reactivates their own account.
func (a accounts) update(ctx context.Context, organizationID, userID uuid.UUID, input UpdateInput, actor audit.Actor) (*User, error) {
	var user *User
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		q := a.repo.q.WithTx(tx)
		previous, err := q.LockAccountStatus(ctx, dbgen.LockAccountStatusParams{OrganizationID: organizationID, ID: userID})
		if err != nil {
			return errs.ErrNotFound
		}
		if input.Status != nil && *input.Status == "active" && previous == "suspended" && isSelf(actor, userID) {
			return errs.ErrForbidden
		}
		before, err := a.repo.GetTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		if user, err = a.repo.UpdateTx(ctx, tx, userID, input); err != nil {
			return err
		}
		if changed := profileChanges(before, input); len(changed) > 0 {
			if err := audit.Record(ctx, tx, actor.Event(organizationID, "user.updated", "user", userID,
				map[string]any{"changed": changed})); err != nil {
				return err
			}
		}
		if input.Status == nil || previous == *input.Status {
			return nil
		}
		action, reason := "user.reactivated", sessionsignal.ReasonReactivated
		if *input.Status == "suspended" {
			action, reason = "user.suspended", sessionsignal.ReasonSuspended
			if err := q.MarkSuspendedManually(ctx, dbgen.MarkSuspendedManuallyParams{OrganizationID: organizationID, ID: userID}); err != nil {
				return err
			}
		}
		if err := a.endEverySignIn(ctx, tx, userID, reason); err != nil {
			return err
		}
		return recordAccountChange(ctx, tx, actor, organizationID, userID, action)
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// reactivate reactivates userID, a suspended account of organizationID,
// ending every way it was signed in before, recorded as user.reactivated.
// ErrConflict when it isn't suspended; nobody reactivates their own account.
func (a accounts) reactivate(ctx context.Context, organizationID, userID uuid.UUID, actor audit.Actor) (*User, error) {
	if isSelf(actor, userID) {
		return nil, errs.ErrForbidden
	}
	var user *User
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		status, err := a.repo.q.WithTx(tx).LockAccountStatus(ctx, dbgen.LockAccountStatusParams{OrganizationID: organizationID, ID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrNotFound
		}
		if err != nil {
			return err
		}
		if status != "suspended" {
			return errs.ErrConflict
		}
		active := "active"
		if user, err = a.repo.UpdateTx(ctx, tx, userID, UpdateInput{Status: &active}); err != nil {
			return err
		}
		if err := a.endEverySignIn(ctx, tx, userID, sessionsignal.ReasonReactivated); err != nil {
			return err
		}
		return recordAccountChange(ctx, tx, actor, organizationID, userID, "user.reactivated")
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// suspensionReview is an administrator's review of a suspension.
type suspensionReview struct {
	Reason string `json:"reason"`
	Risk   string `json:"risk"`
	Review string `json:"review"`
}

// reviewSuspension records review of userID's suspension in organizationID,
// as user.suspension_reviewed. ErrConflict when the account isn't the
// organization's or isn't suspended.
func (a accounts) reviewSuspension(ctx context.Context, organizationID, userID uuid.UUID, review suspensionReview, actor audit.Actor) error {
	return a.inTx(ctx, func(tx pgx.Tx) error {
		n, err := a.repo.q.WithTx(tx).ReviewSuspension(ctx, dbgen.ReviewSuspensionParams{
			Reason: review.Reason, Risk: review.Risk, Review: review.Review, OrganizationID: organizationID, ID: userID,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return errs.ErrConflict
		}
		return recordAccountChange(ctx, tx, actor, organizationID, userID, "user.suspension_reviewed")
	})
}

// isSelf reports whether actor is the person userID.
func isSelf(actor audit.Actor, userID uuid.UUID) bool {
	return actor.UserID != nil && *actor.UserID == userID
}
