package user

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// A person has one account, with one password and set of second factors, in
// every organization they belong to. So an organization may set the password or
// reset the factors only while the account belongs to it alone; after that only
// the person can, though each organization can still suspend or remove it.

// refuseSharedCredentials refuses, with ErrUserCredentialsShared, an
// organization's credential change for an account that also belongs to
// another live organization.
func (h *Handler) refuseSharedCredentials(ctx context.Context, userID, organizationID uuid.UUID) error {
	var shared bool
	if err := h.Repo.Pool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM rbac.user_roles ur
			JOIN organization.organizations t ON t.id = ur.organization_id AND t.deleted_at IS NULL
			WHERE ur.user_id = $1 AND ur.organization_id <> $2
		)`, userID, organizationID).Scan(&shared); err != nil {
		return err
	}
	if shared {
		return errs.ErrUserCredentialsShared
	}
	return nil
}

// credentialChange is the kind of credential change an administrator made.
type credentialChange int

const (
	credentialPasswordSet credentialChange = iota
	credentialFactorsReset
	credentialPasskeyRemoved
)

// tellCredentialChange emails the person that an administrator of organizationID
// changed their credentials; passkey names the passkey removed, if any. Best
// effort, after the change has committed: a failure is logged, the change stands.
func (h *Handler) tellCredentialChange(ctx context.Context, organizationID uuid.UUID, email string, change credentialChange, passkey string) {
	if h.Mailer == nil || email == "" {
		return
	}
	org := "your organization"
	var name string
	if err := h.Repo.Pool().QueryRow(ctx, `SELECT name FROM organization.organizations WHERE id = $1`, organizationID).Scan(&name); err == nil && name != "" {
		org = name
	}
	subject, intro := "An administrator set a new password for your account",
		fmt.Sprintf("An administrator of %s set a new password for your Qeet ID account, and signed you out everywhere.", org)
	switch change {
	case credentialFactorsReset:
		subject, intro = "An administrator reset your two-step verification",
			fmt.Sprintf("An administrator of %s removed the two-step verification from your Qeet ID account. You'll be asked to set it up again at your next sign-in.", org)
	case credentialPasskeyRemoved:
		subject, intro = "An administrator removed a passkey from your account",
			fmt.Sprintf("An administrator of %s removed a passkey from your Qeet ID account, so it no longer signs you in.", org)
		if passkey != "" {
			intro = fmt.Sprintf("An administrator of %s removed the passkey %q from your Qeet ID account, so it no longer signs you in.", org, passkey)
		}
	}
	const note = "If you didn't expect this, contact that organization's administrator."
	if err := h.Mailer.Send(ctx, notifier.Message{
		Channel:        "email",
		To:             email,
		OrganizationID: organizationID.String(),
		Subject:        subject,
		Body:           intro + " " + note,
		HTML:           emailtmpl.Notice(subject, intro, note),
	}); err != nil {
		slog.Warn("credential change notice not sent", "err", err, "tenant_id", organizationID)
	}
}
