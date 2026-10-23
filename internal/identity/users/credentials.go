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
// every organisation they belong to. So an organisation may set the password or
// reset the factors only while the account belongs to it alone; after that only
// the person can, though each organisation can still suspend or remove it.

// refuseSharedCredentials refuses, with ErrUserCredentialsShared, an
// organisation's credential change for an account that also belongs to
// another live organisation.
func (h *Handler) refuseSharedCredentials(ctx context.Context, userID, tenantID uuid.UUID) error {
	var shared bool
	if err := h.Repo.Pool().QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM rbac.user_roles ur
			JOIN tenant.tenants t ON t.id = ur.tenant_id AND t.deleted_at IS NULL
			WHERE ur.user_id = $1 AND ur.tenant_id <> $2
		)`, userID, tenantID).Scan(&shared); err != nil {
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
)

// tellCredentialChange emails the person that an administrator of tenantID
// changed their credentials. Best effort, after the change has committed: a
// failure is logged, the change stands.
func (h *Handler) tellCredentialChange(ctx context.Context, tenantID uuid.UUID, email string, change credentialChange) {
	if h.Mailer == nil || email == "" {
		return
	}
	org := "your organization"
	var name string
	if err := h.Repo.Pool().QueryRow(ctx, `SELECT name FROM tenant.tenants WHERE id = $1`, tenantID).Scan(&name); err == nil && name != "" {
		org = name
	}
	subject, intro := "An administrator set a new password for your account",
		fmt.Sprintf("An administrator of %s set a new password for your Qeet ID account, and signed you out everywhere.", org)
	if change == credentialFactorsReset {
		subject, intro = "An administrator reset your two-step verification",
			fmt.Sprintf("An administrator of %s removed the two-step verification from your Qeet ID account. You'll be asked to set it up again at your next sign-in.", org)
	}
	const note = "If you didn't expect this, contact that organization's administrator."
	if err := h.Mailer.Send(ctx, notifier.Message{
		Channel:  "email",
		To:       email,
		TenantID: tenantID.String(),
		Subject:  subject,
		Body:     intro + " " + note,
		HTML:     emailtmpl.Notice(subject, intro, note),
	}); err != nil {
		slog.Warn("credential change notice not sent", "err", err, "tenant_id", tenantID)
	}
}
