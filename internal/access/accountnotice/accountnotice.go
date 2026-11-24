// Package accountnotice emails an account holder that the way they sign in
// changed, so a change they didn't make is noticed. The email names what
// changed and how to get the account back, and never holds a secret.
package accountnotice

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/accountnotice/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// wasntYou is the note every notice ends with: how to get the account back.
const wasntYou = "If this wasn't you, reset your password from the sign-in page and contact your organization's administrator right away."

// Tell emails userID's address subject and intro, with the note on what to do
// if it wasn't them. Best effort, after the change has committed: a failure is
// logged and the change stands. A nil sender sends nothing.
func Tell(ctx context.Context, db postgres.Querier, sender notifier.Sender, userID uuid.UUID, subject, intro string) {
	if sender == nil {
		return
	}
	to, err := dbgen.New(db).NoticeAddress(ctx, userID)
	if err != nil || to.Email == "" {
		slog.Warn("account notice not sent: no address", "err", err, "user_id", userID, "subject", subject)
		return
	}
	msg := notifier.Message{
		Channel: "email",
		To:      to.Email,
		Subject: subject,
		Body:    intro + " " + wasntYou,
		HTML:    emailtmpl.Notice(subject, intro, wasntYou),
	}
	if to.OrganizationID != nil {
		msg.OrganizationID = to.OrganizationID.String()
	}
	if err := sender.Send(ctx, msg); err != nil {
		slog.Warn("account notice not sent", "err", err, "user_id", userID, "subject", subject)
	}
}
