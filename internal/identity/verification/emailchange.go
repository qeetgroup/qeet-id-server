package verification

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// changeEmailDigits is an email-change code's length: confirming one moves the
// account's sign-in address, so it is longer than the other codes' six.
const changeEmailDigits = 8

// StartEmailChange sends a code to the address the user wants to move to, to
// prove they control it. An address another account holds (email is unique
// platform-wide) is sent a notice instead, and the caller gets the same answer,
// so the reply doesn't show whether the address has an account.
func (s *Service) StartEmailChange(ctx context.Context, userID uuid.UUID, newEmail string, who Requester) error {
	newEmail = strings.TrimSpace(newEmail)
	if newEmail == "" {
		return ErrVerifyNoEmail
	}
	if err := checkEmailChange(ctx, s.pool, userID, newEmail); err != nil {
		return err
	}
	taken, err := s.q.EmailTakenByOther(ctx, dbgen.EmailTakenByOtherParams{
		Email:  newEmail,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	// A code is stored either way, so it supersedes an earlier one and counts
	// against the limits alike. One for a held address is never sent, and
	// confirming it couldn't assign it.
	code, id, err := s.issueEmailCode(ctx, userID, newEmail, purposeChangeEmail, who)
	if err != nil {
		return err
	}
	if taken {
		return s.withdrawUndelivered(ctx, s.q.DeleteEmailVerification, id, s.noticeAddressInUse(ctx, newEmail))
	}
	expiry := fmt.Sprintf("%d minutes", int(s.ttl.Minutes()))
	return s.withdrawUndelivered(ctx, s.q.DeleteEmailVerification, id, s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      newEmail,
		Subject: "Confirm your new email",
		Body:    fmt.Sprintf("Your Qeet ID email-change code is %s. It expires in %s.", code, expiry),
		HTML: emailtmpl.Code(
			"Confirm your new email",
			"Use the code below to confirm your new email address.",
			code, expiry,
		),
	}))
}

// checkEmailChange refuses, with ErrVerifyEmailManaged, moving userID's address to newEmail where an
// organization decides it: its directory or SSO provides the address, the address is on a domain the
// account's organization manages and newEmail isn't, or newEmail is on a domain another organization
// manages. db is the pool, or the confirming transaction.
func checkEmailChange(ctx context.Context, db dbgen.DBTX, userID uuid.UUID, newEmail string) error {
	holder, err := dbgen.New(db).AddressHolder(ctx, userID)
	if err != nil {
		return err
	}
	if holder.Provided {
		return ErrVerifyEmailManaged.WithMessage("Your organization's directory or single sign-on provides your email address, so it changes there.")
	}
	home := postgres.ZeroIfNull(holder.OrganizationID)
	ctx = postgres.AcrossOrganizations(ctx)
	next, ok, err := domainverify.ManagingDomain(ctx, db, newEmail)
	if err != nil {
		return err
	}
	if ok && next.OrganizationID != home {
		return ErrVerifyEmailManaged.WithMessage("That address is on a domain another organization manages.")
	}
	if ok {
		return nil
	}
	current, ok, err := domainverify.ManagingDomain(ctx, db, holder.Email)
	if err != nil {
		return err
	}
	if ok && current.OrganizationID == home {
		return ErrVerifyEmailManaged.WithMessage("Your organization manages your email address's domain, so it can change only to another address on its domains.")
	}
	return nil
}

// noticeAddressInUse tells an address another account holds that it was asked
// for, and why no code came.
func (s *Service) noticeAddressInUse(ctx context.Context, email string) error {
	intro := "Someone asked to use this email address for a Qeet ID account, but it already belongs to another Qeet ID account, so it can't be used."
	note := "If that was you, sign in with the account that uses this address. If it wasn't, you can ignore this email."
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "This email address already has an account",
		Body:    intro + " " + note,
		HTML:    emailtmpl.Notice("This email address already has an account", intro, note),
	})
}

// ConfirmEmailChange verifies the change_email code sent to the new address and
// swaps it onto the user (marking it verified), audits both addresses and tells
// the previous one. Returns the new email on success. A unique violation
// (address claimed between start and confirm) maps to ErrEmailTaken.
func (s *Service) ConfirmEmailChange(ctx context.Context, userID uuid.UUID, code string, who Requester) (string, error) {
	oldEmail, newEmail, err := s.confirmEmailChange(ctx, userID, code, who)
	if err != nil {
		return "", s.auditRefusal(ctx, "email.verification_failed", userID, map[string]any{"purpose": purposeChangeEmail}, who, err)
	}
	if !strings.EqualFold(oldEmail, newEmail) {
		s.noticeEmailChanged(ctx, userID, oldEmail, newEmail)
	}
	return newEmail, nil
}

func (s *Service) confirmEmailChange(ctx context.Context, userID uuid.UUID, code string, who Requester) (string, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	row, err := newestEmailCode(ctx, qtx, userID, purposeChangeEmail)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrVerifyCodeInvalid
		}
		return "", "", err
	}
	budget, err := emailBudget(ctx, tx, userID, purposeChangeEmail)
	if err != nil {
		return "", "", err
	}
	if err := chargeFailure(ctx, tx, row, code, budget); err != nil {
		return "", "", err
	}
	// Checked again: an organization may have verified a domain since the start.
	if err := checkEmailChange(ctx, tx, userID, row.value); err != nil {
		return "", "", err
	}
	oldEmail, err := qtx.GetUserEmail(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if err := qtx.MarkEmailVerificationUsed(ctx, row.id); err != nil {
		return "", "", err
	}
	// Links already sent to the old address stop working with it.
	if err := qtx.ExpireRecoveryLinksForUser(ctx, userID); err != nil {
		return "", "", err
	}
	if _, err := qtx.UpdateUserEmail(ctx, dbgen.UpdateUserEmailParams{
		Email:  row.value,
		UserID: userID,
	}); err != nil {
		if postgres.IsUnique(err) {
			return "", "", ErrEmailTaken
		}
		return "", "", err
	}
	if err := audit.Record(ctx, tx, who.event("email.changed", userID,
		map[string]any{"old_email": oldEmail, "new_email": row.value})); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return oldEmail, row.value, nil
}

// noticeEmailChanged tells the previous address that the account moved, so its
// owner learns of a change they didn't make. Best-effort: the change is done.
func (s *Service) noticeEmailChanged(ctx context.Context, userID uuid.UUID, oldEmail, newEmail string) {
	intro := fmt.Sprintf("The email address on your Qeet ID account was changed from %s to %s.", oldEmail, newEmail)
	note := "If you made this change, there is nothing to do. If you didn't, contact your organization's administrator right away."
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      oldEmail,
		Subject: "Your email address was changed",
		Body:    intro + " " + note,
		HTML:    emailtmpl.Notice("Your email address was changed", intro, note),
	}); err != nil {
		slog.Warn("verification: could not send the email-change notice", "user_id", userID, "err", err)
	}
}
