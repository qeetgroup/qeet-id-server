package passkey

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// EnrolmentAllowed reports whether the user may add a passkey: false when
// their organization has passkeys switched off.
func (s *Service) EnrolmentAllowed(ctx context.Context, userID uuid.UUID) (bool, error) {
	row, err := s.q.GetUserForWebAuthn(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrUserNotFound
	}
	if err != nil {
		return false, err
	}
	var organizationID uuid.UUID
	if row.OrganizationID != nil {
		organizationID = *row.OrganizationID
	}
	err = s.passkeysAllowed(ctx, organizationID)
	if errors.Is(err, ErrDisabled) {
		return false, nil
	}
	return err == nil, err
}

// List returns the user's passkeys.
func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Credential, error) {
	rows, err := s.q.ListPasskeyCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(rows))
	for _, m := range rows {
		out = append(out, credentialFromRow(m))
	}
	return out, nil
}

func credentialFromRow(m dbgen.ListPasskeyCredentialsRow) Credential {
	return Credential{
		ID:         m.ID,
		UserID:     m.UserID,
		Name:       m.Name,
		Transports: m.Transports,
		LastUsedAt: m.LastUsedAt,
		CreatedAt:  m.CreatedAt,
	}
}

// Rename sets the name of one of the user's passkeys, recorded as who's. The
// name is cleaned and checked (see validName). Like Delete it is scoped to the
// owner: another user's passkey is not found, and is left unchanged.
func (s *Service) Rename(ctx context.Context, id, userID uuid.UUID, name string, who Requester) (*Credential, error) {
	name, err := validName(name)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	previous, err := q.LockPasskeyCredentialName(ctx, dbgen.LockPasskeyCredentialNameParams{ID: id, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	row, err := q.RenamePasskeyCredential(ctx, dbgen.RenamePasskeyCredentialParams{
		Name:   &name,
		ID:     id,
		UserID: userID,
	})
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, who.event("passkey.renamed", userID,
		map[string]any{"passkey_id": id, "name": name, "previous_name": strutil.Deref(previous)})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	c := credentialFromRow(dbgen.ListPasskeyCredentialsRow(row))
	return &c, nil
}

// Delete removes one of the user's own passkeys, recorded as who's, and tells
// the account holder. Another user's passkey is ErrNotFound and nothing is
// deleted; removing the account's only way to sign in is refused with
// ErrAuthLastSignInMethod, and the refusal recorded.
func (s *Service) Delete(ctx context.Context, id, userID uuid.UUID, who Requester) error {
	// The account's other ways to sign in span its organizations.
	ctx = postgres.AcrossOrganizations(ctx)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	methods, err := user.LockSignInMethods(ctx, tx, userID)
	if err != nil {
		return err
	}
	name, err := s.q.WithTx(tx).DeletePasskeyCredential(ctx, dbgen.DeletePasskeyCredentialParams{
		ID:     id,
		UserID: userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		by := user.Remover{UserID: who.UserID, IP: who.IP, UserAgent: who.UserAgent, RequestID: who.RequestID}
		return user.RefuseLastMethodRemoval(ctx, s.pool, userID, who.OrganizationID, "passkey", id, by)
	}
	if err := audit.Record(ctx, tx, who.event("passkey.deleted", userID,
		map[string]any{"passkey_id": id, "name": strutil.Deref(name)})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.tellPasskeyChange(ctx, userID, passkeyRemoved, strutil.Deref(name))
	return nil
}

// passkeyChange is what happened to one of a person's passkeys.
type passkeyChange int

// tellPasskeyChange emails the account holder that a passkey was added to or
// removed from their account, so one they didn't add is noticed. Best effort,
// after the change has committed: a failure is logged, the change stands.
func (s *Service) tellPasskeyChange(ctx context.Context, userID uuid.UUID, change passkeyChange, name string) {
	if s.sender == nil {
		return
	}
	account, err := s.q.GetUserForWebAuthn(ctx, userID)
	if err != nil || account.Email == "" {
		slog.Warn("passkey change notice not sent: no address", "err", err, "user_id", userID)
		return
	}
	subject, intro := "A passkey was added to your account",
		fmt.Sprintf("A passkey named “%s” was added to your Qeet ID account and can now be used to sign in.", name)
	note := "If you didn't add it, remove it from your account's security settings and contact your organization's administrator right away."
	if change == passkeyRemoved {
		subject, intro = "A passkey was removed from your account",
			fmt.Sprintf("The passkey named “%s” was removed from your Qeet ID account and can no longer be used to sign in.", name)
		note = "If you didn't remove it, contact your organization's administrator right away."
	}
	msg := notifier.Message{Channel: "email", To: account.Email, Subject: subject, Body: intro + " " + note, HTML: emailtmpl.Notice(subject, intro, note)}
	if account.OrganizationID != nil {
		msg.OrganizationID = account.OrganizationID.String()
	}
	if err := s.sender.Send(ctx, msg); err != nil {
		slog.Warn("passkey change notice not sent", "err", err, "user_id", userID)
	}
}

const (
	passkeyAdded passkeyChange = iota
	passkeyRemoved
)

// Credential is one of a person's registered passkeys.
type Credential struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Name       *string    `json:"name"`
	Transports []string   `json:"transports"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}
