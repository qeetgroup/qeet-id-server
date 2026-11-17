// Package accountnotice emails an account holder that the way they sign in
// changed, so a change they didn't make is noticed. The email names what
// changed and how to get the account back, and never holds a secret.
package accountnotice

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// wasntYou is the note every notice ends with: how to get the account back.
const wasntYou = "If this wasn't you, reset your password from the sign-in page and contact your organization's administrator right away."

// Querier is the slice of a pool or transaction Tell reads with.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Tell emails userID's address subject and intro, with the note on what to do
// if it wasn't them. Best effort, after the change has committed: a failure is
// logged and the change stands. A nil sender sends nothing.
func Tell(ctx context.Context, db Querier, sender notifier.Sender, userID uuid.UUID, subject, intro string) {
	if sender == nil {
		return
	}
	var email string
	var organizationID *uuid.UUID
	if err := db.QueryRow(ctx, `SELECT email, organization_id FROM account.users WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&email, &organizationID); err != nil || email == "" {
		slog.Warn("account notice not sent: no address", "err", err, "user_id", userID, "subject", subject)
		return
	}
	msg := notifier.Message{
		Channel: "email",
		To:      email,
		Subject: subject,
		Body:    intro + " " + wasntYou,
		HTML:    emailtmpl.Notice(subject, intro, wasntYou),
	}
	if organizationID != nil {
		msg.OrganizationID = organizationID.String()
	}
	if err := sender.Send(ctx, msg); err != nil {
		slog.Warn("account notice not sent", "err", err, "user_id", userID, "subject", subject)
	}
}
