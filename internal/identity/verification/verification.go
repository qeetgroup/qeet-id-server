// Package verification proves a user controls an email address or phone number
// by sending a one-time code, both to verify the address on file and to change
// the account's email. Codes go out through a notifier.Sender.
package verification

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service proves a user controls an email address or phone number, by a code
// sent to it.
type Service struct {
	pool        *pgxpool.Pool
	q           *dbgen.Queries
	sender      notifier.Sender
	ttl         time.Duration
	plan        PlanGate                  // gates SMS codes by plan (nil = no gate)
	deliverable func(channel string) bool // whether a channel can deliver (nil = assume it can)
}

// PlanGate reports whether an organisation's plan includes a feature.
// Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// SetPlan wires the plan gate for SMS codes, which cost per message.
func (s *Service) SetPlan(p PlanGate) { s.plan = p }

// SetDeliveryCheck wires the check that a channel can deliver a code
// (notifier.Router.Configured).
func (s *Service) SetDeliveryCheck(deliverable func(channel string) bool) {
	s.deliverable = deliverable
}

// Requester is who asked, for the audit trail: the actor, and the organization
// their session is in (nil before they belong to one).
type Requester struct {
	Actor    audit.Actor
	TenantID *uuid.UUID
}

func (r Requester) event(action string, userID uuid.UUID, metadata map[string]any) audit.Event {
	e := r.Actor.PlatformEvent(action, "user", userID, metadata)
	e.TenantID = r.TenantID
	return e
}

// The two flows that send email codes. A code proves only what its own flow
// asked: a verify_email code went to the address on file, a change_email code
// to the address the user wants to move to.
const (
	purposeVerifyEmail = "verify_email"
	purposeChangeEmail = "change_email"
)

// NewService returns the verification service.
func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl}
}

// latestCode is the newest outstanding verification row for a user, together
// with the hash of the code it was issued for.
type latestCode struct {
	id        uuid.UUID  // the row ID
	codeHash  string     // hash of the code
	value     string     // the email or phone carried on the row
	expiresAt time.Time  // when the code expires
	usedAt    *time.Time // when it was used; nil if unused
	attempts  int        // wrong guesses so far
}

// Limits on guessing and sending codes. Five wrong answers retire a code, and
// a person gets ten an hour at each flow's codes however many they ask for, so
// a resend brings no fresh budget; codes go out at the pace of a person asking,
// as MFA codes do, so nobody can flood an inbox or phone or run up SMS bills.
const (
	maxVerificationAttempts     = 5                // wrong guesses that retire one code
	verificationFailuresPerHour = 10               // wrong guesses per person and flow per hour, over all its codes
	codeResendAfter             = 30 * time.Second // wait before a person's next SMS code
	codeSendsPerHourPerUser     = 10               // codes per person per hour, by email or by SMS
	codeSendsPerHourPerAddress  = 5                // codes per address or number per hour, over all accounts
)

// e164 matches a phone number in E.164 form: +, a country code, at most 15 digits.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// errVerifyPhoneInvalid refuses a number that isn't in E.164 form.
var errVerifyPhoneInvalid = errs.ErrValidationFailed.WithFields([]errs.FieldError{{
	Field: "phone", Code: "invalid_phone", Message: "Must be a valid phone number in E.164 format.",
}})

// changeEmailDigits is an email-change code's length: confirming one moves the
// account's sign-in address, so it is longer than the other codes' six.
const changeEmailDigits = 8

// errVerifyFailuresPerHour refuses a confirm once the hour's guesses are spent.
var errVerifyFailuresPerHour = errs.ErrVerifyAttemptsExceeded.WithMessage("Too many incorrect codes. Try again later.")

// guessBudget is how many wrong guesses a person made at one flow's codes in
// the last hour, and when the oldest code they hit was sent.
type guessBudget struct {
	failures int
	oldest   time.Time
}

// spent returns the refusal, with retry_after in seconds, once b is used up.
func (b guessBudget) spent() error {
	if b.failures < verificationFailuresPerHour {
		return nil
	}
	return errVerifyFailuresPerHour.WithMetadata(map[string]any{"retry_after": retryAfter(time.Until(b.oldest.Add(time.Hour)))})
}

// retryAfter is wait in whole seconds, at least one.
func retryAfter(wait time.Duration) int { return max(1, int(wait.Round(time.Second).Seconds())) }

// codeSends are the codes of the last hour that count against one more: the
// person's and the address's (by anyone), each with when the oldest went, and
// for SMS when the person's last went.
type codeSends struct {
	mine, toAddress           int32
	mineOldest, addressOldest time.Time
	last                      time.Time // zero: no wait between codes
}

// limit refuses one more code with ErrVerifyCodeSendLimited (retry_after in
// seconds) within codeResendAfter of last, or once an hourly limit is reached.
func (c codeSends) limit() error {
	var wait time.Duration
	if !c.last.IsZero() {
		wait = codeResendAfter - time.Since(c.last)
	}
	if c.mine >= codeSendsPerHourPerUser {
		wait = max(wait, time.Until(c.mineOldest.Add(time.Hour)))
	}
	if c.toAddress >= codeSendsPerHourPerAddress {
		wait = max(wait, time.Until(c.addressOldest.Add(time.Hour)))
	}
	if wait <= 0 {
		return nil
	}
	return errs.ErrVerifyCodeSendLimited.WithMetadata(map[string]any{"retry_after": retryAfter(wait)})
}

// matches reports whether the submitted code is the one this row was issued
// for, compared in constant time so a wrong code can't be recovered by timing.
func (l latestCode) matches(code string) bool {
	return subtle.ConstantTimeCompare([]byte(codes.Hash(code)), []byte(l.codeHash)) == 1
}

// newestEmailCode locks and returns userID's most recent email code for purpose.
// It doesn't filter on the submitted code, so only the newest code can match: a
// resend supersedes the code before it. Hand-written SQL, not sqlc.
func newestEmailCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID, purpose string) (latestCode, error) {
	var l latestCode
	err := tx.QueryRow(ctx, `
		SELECT id, code_hash, email, expires_at, used_at, attempts
		FROM account.email_verifications
		WHERE user_id = $1 AND purpose = $2
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE
	`, userID, purpose).Scan(&l.id, &l.codeHash, &l.value, &l.expiresAt, &l.usedAt, &l.attempts)
	return l, err
}

// newestPhoneCode is newestEmailCode for phone codes.
func newestPhoneCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (latestCode, error) {
	var l latestCode
	err := tx.QueryRow(ctx, `
		SELECT id, code_hash, phone, expires_at, used_at, attempts
		FROM account.phone_verifications
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE
	`, userID).Scan(&l.id, &l.codeHash, &l.value, &l.expiresAt, &l.usedAt, &l.attempts)
	return l, err
}

// recordFailedAttempt charges one guess against code row id and reports whether
// that exhausted the budget, retiring the code on the guess that hits the cap.
// The caller must commit even though it then returns an error, or the count is
// lost and the budget is unlimited.
func recordFailedAttempt(ctx context.Context, tx pgx.Tx, table string, id uuid.UUID) (bool, error) {
	// #nosec G201 -- table is one of two package-local literals, never caller input.
	q := `UPDATE account.` + table + `
		SET attempts = attempts + 1,
		    used_at  = CASE WHEN attempts + 1 >= $2 THEN NOW() ELSE used_at END
		WHERE id = $1
		RETURNING attempts >= $2`
	var exhausted bool
	err := tx.QueryRow(ctx, q, id, maxVerificationAttempts).Scan(&exhausted)
	return exhausted, err
}

// chargeFailure runs the shared checks and, when the submitted code is wrong,
// persists the failed attempt before returning. It commits the transaction on
// that path so the count survives the caller's deferred rollback. A spent
// budget refuses even the right code, as a retired code does.
func chargeFailure(ctx context.Context, tx pgx.Tx, table string, row latestCode, code string, budget guessBudget) error {
	if err := budget.spent(); err != nil {
		return err
	}
	err := checkUsable(row, code)
	if !errors.Is(err, errs.ErrVerifyCodeInvalid) {
		// Expired, already used, or budget already gone: nothing to charge, and
		// a correct code (err == nil) falls through to the caller's success path.
		return err
	}
	exhausted, updErr := recordFailedAttempt(ctx, tx, table, row.id)
	if updErr != nil {
		return updErr
	}
	if cmtErr := tx.Commit(ctx); cmtErr != nil {
		return cmtErr
	}
	if exhausted {
		return errs.ErrVerifyAttemptsExceeded
	}
	budget.failures++
	if err := budget.spent(); err != nil {
		return err
	}
	return err
}

// checkUsable applies the non-identity checks shared by every confirm path.
func checkUsable(l latestCode, code string) error {
	// Budget first, and before the identity check: once a code is burned it is
	// dead even for the correct value, so a guesser can't tell from the response
	// that they had finally landed on it.
	if l.attempts >= maxVerificationAttempts {
		return errs.ErrVerifyAttemptsExceeded
	}
	// A stale code (superseded by a resend) and a plain wrong code are the same
	// thing to the caller: this is not the code we are waiting on.
	if !l.matches(code) {
		return errs.ErrVerifyCodeInvalid
	}
	if l.usedAt != nil {
		return errs.ErrVerifyCodeUsed
	}
	if time.Now().After(l.expiresAt) {
		return errs.ErrVerifyCodeExpired
	}
	return nil
}

// StartEmail sends a verification code to the user's email address.
func (s *Service) StartEmail(ctx context.Context, userID uuid.UUID, email string, who Requester) error {
	// Default to the address on file so the caller doesn't have to pass their
	// own email just to verify it (POST .../verify/email/start with no body).
	if strings.TrimSpace(email) == "" {
		addr, err := s.q.GetUserEmail(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.ErrVerifyUserNotFound
			}
			return err
		}
		email = addr
	}
	if strings.TrimSpace(email) == "" {
		return errs.ErrVerifyNoEmail
	}
	code, id, err := s.issueEmailCode(ctx, userID, email, purposeVerifyEmail, who)
	if err != nil {
		return err
	}
	expiry := fmt.Sprintf("%d minutes", int(s.ttl.Minutes()))
	return s.withdrawUndelivered(ctx, s.q.DeleteEmailVerification, id, s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Verify your email",
		Body:    fmt.Sprintf("Your Qeet ID verification code is %s. It expires in %s.", code, expiry),
		HTML: emailtmpl.Code(
			"Verify your email",
			"Use the code below to verify your email address.",
			code, expiry,
		),
	}))
}

// withdrawUndelivered deletes code row id with remove when sendErr says the
// provider didn't take it, so nobody can use a code its holder never got, and
// returns sendErr. Best effort: the send already failed.
func (s *Service) withdrawUndelivered(ctx context.Context, remove func(context.Context, uuid.UUID) error, id uuid.UUID, sendErr error) error {
	if sendErr != nil {
		if err := remove(ctx, id); err != nil {
			slog.Warn("verification: could not withdraw an undelivered code", "code_id", id, "err", err)
		}
	}
	return sendErr
}

// issueEmailCode stores a new code for one purpose (expiring the user's open
// codes) and audits it, in one transaction, unless the sending limits refuse
// it. It returns the code to send and its row.
func (s *Service) issueEmailCode(ctx context.Context, userID uuid.UUID, email, purpose string, who Requester) (string, uuid.UUID, error) {
	digits := 6
	if purpose == purposeChangeEmail {
		digits = changeEmailDigits
	}
	code, err := codes.Numeric(digits)
	if err != nil {
		return "", uuid.Nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	if err := qtx.LockAccountForCodeSend(ctx, userID); err != nil {
		return "", uuid.Nil, err
	}
	sent, err := qtx.EmailCodeSends(ctx, dbgen.EmailCodeSendsParams{UserID: userID, Email: email})
	if err != nil {
		return "", uuid.Nil, err
	}
	if err := (codeSends{mine: sent.UserSends, mineOldest: sent.UserOldest, toAddress: sent.AddressSends,
		addressOldest: sent.AddressOldest}).limit(); err != nil {
		return "", uuid.Nil, err
	}
	id, err := qtx.InsertEmailVerification(ctx, dbgen.InsertEmailVerificationParams{
		UserID:    userID,
		Email:     email,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
		Purpose:   purpose,
	})
	if err != nil {
		return "", uuid.Nil, err
	}
	if err := audit.Record(ctx, tx, who.event("email.verification_started", userID,
		map[string]any{"purpose": purpose, "email": email})); err != nil {
		return "", uuid.Nil, err
	}
	return code, id, tx.Commit(ctx)
}

// emailBudget returns userID's guesses at purpose's codes this hour, in tx.
func emailBudget(ctx context.Context, tx pgx.Tx, userID uuid.UUID, purpose string) (guessBudget, error) {
	row, err := dbgen.New(tx).EmailCodeFailures(ctx, dbgen.EmailCodeFailuresParams{UserID: userID, Purpose: purpose})
	return guessBudget{failures: int(row.Failures), oldest: row.Oldest}, err
}

// ConfirmEmail verifies the address on file with a verify_email code. The code
// must have been sent to that address: one sent elsewhere (for an address
// change, or before the address changed) is the invalid-code error.
func (s *Service) ConfirmEmail(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	err := s.confirmEmail(ctx, userID, code, who)
	return s.auditRefusal(ctx, "email.verification_failed", userID, map[string]any{"purpose": purposeVerifyEmail}, who, err)
}

func (s *Service) confirmEmail(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	row, err := newestEmailCode(ctx, tx, userID, purposeVerifyEmail)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrVerifyCodeInvalid
		}
		return err
	}
	budget, err := emailBudget(ctx, tx, userID, purposeVerifyEmail)
	if err != nil {
		return err
	}
	if err := chargeFailure(ctx, tx, "email_verifications", row, code, budget); err != nil {
		return err
	}
	n, err := qtx.MarkUserEmailVerified(ctx, dbgen.MarkUserEmailVerifiedParams{UserID: userID, Email: row.value})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrVerifyCodeInvalid
	}
	if err := qtx.MarkEmailVerificationUsed(ctx, row.id); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, who.event("email.verified", userID,
		map[string]any{"email": row.value, "proof": "emailed_code"})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// auditRefusal records a refused confirm (a wrong, stale, used or exhausted
// code) as action, with metadata and the reason, in its own transaction since
// the confirm's own has ended. Any other error, and success, pass through.
func (s *Service) auditRefusal(ctx context.Context, action string, userID uuid.UUID, metadata map[string]any, who Requester, err error) error {
	e := errs.As(err)
	if e == nil || !isCodeRefusal(err) {
		return err
	}
	tx, txErr := s.pool.Begin(ctx)
	if txErr != nil {
		return txErr
	}
	defer tx.Rollback(ctx)
	metadata["reason"] = e.Code
	if aerr := audit.Record(ctx, tx, who.event(action, userID, metadata)); aerr != nil {
		return aerr
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return cerr
	}
	return err
}

// isCodeRefusal reports whether err is one of the answers to a bad code.
func isCodeRefusal(err error) bool {
	return errors.Is(err, errs.ErrVerifyCodeInvalid) || errors.Is(err, errs.ErrVerifyCodeExpired) ||
		errors.Is(err, errs.ErrVerifyCodeUsed) || errors.Is(err, errs.ErrVerifyAttemptsExceeded)
}

// StartEmailChange sends a code to the address the user wants to move to, to
// prove they control it. An address another account holds (email is unique
// platform-wide) is sent a notice instead, and the caller gets the same answer,
// so the reply doesn't show whether the address has an account.
func (s *Service) StartEmailChange(ctx context.Context, userID uuid.UUID, newEmail string, who Requester) error {
	newEmail = strings.TrimSpace(newEmail)
	if newEmail == "" {
		return errs.ErrVerifyNoEmail
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

// checkEmailChange refuses, with ErrVerifyEmailManaged, moving userID's address
// to newEmail where an organisation decides it: its directory or single
// sign-on provides the address, the address is on a domain the account's
// organisation manages and newEmail isn't, or newEmail is on a domain another
// organisation manages. db is the pool, or the confirming transaction.
func checkEmailChange(ctx context.Context, db dbgen.DBTX, userID uuid.UUID, newEmail string) error {
	holder, err := dbgen.New(db).AddressHolder(ctx, userID)
	if err != nil {
		return err
	}
	if holder.Provided {
		return errs.ErrVerifyEmailManaged.WithMessage("Your organization's directory or single sign-on provides your email address, so it changes there.")
	}
	home := uuid.UUID(holder.TenantID.Bytes)
	ctx = postgres.AcrossTenants(ctx)
	next, ok, err := domainverify.ManagingDomain(ctx, db, newEmail)
	if err != nil {
		return err
	}
	if ok && next.TenantID != home {
		return errs.ErrVerifyEmailManaged.WithMessage("That address is on a domain another organization manages.")
	}
	if ok {
		return nil
	}
	current, ok, err := domainverify.ManagingDomain(ctx, db, holder.Email)
	if err != nil {
		return err
	}
	if ok && current.TenantID == home {
		return errs.ErrVerifyEmailManaged.WithMessage("Your organization manages your email address's domain, so it can change only to another address on its domains.")
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

	row, err := newestEmailCode(ctx, tx, userID, purposeChangeEmail)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", errs.ErrVerifyCodeInvalid
		}
		return "", "", err
	}
	budget, err := emailBudget(ctx, tx, userID, purposeChangeEmail)
	if err != nil {
		return "", "", err
	}
	if err := chargeFailure(ctx, tx, "email_verifications", row, code, budget); err != nil {
		return "", "", err
	}
	// Checked again: an organisation may have verified a domain since the start.
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
		if pgxerr.IsUnique(err) {
			return "", "", errs.ErrEmailTaken
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

// StartPhone sends a verification code to the user's phone number, recorded as
// who's with the number masked. As for MFA codes, the number must be in E.164
// form, and SMS deliverable and in the plan of the organisation who's session
// is in (none: refused).
func (s *Service) StartPhone(ctx context.Context, userID uuid.UUID, phone string, who Requester) error {
	// Default to the number on file when the body omits it.
	if strings.TrimSpace(phone) == "" {
		stored, err := s.q.GetUserPhone(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.ErrVerifyUserNotFound
			}
			return err
		}
		if stored == nil || strings.TrimSpace(*stored) == "" {
			return errs.ErrVerifyNoPhone
		}
		phone = *stored
	}
	if err := s.canSendSMS(ctx, phone, who.TenantID); err != nil {
		return err
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	if err := qtx.LockAccountForCodeSend(ctx, userID); err != nil {
		return err
	}
	sent, err := qtx.PhoneCodeSends(ctx, dbgen.PhoneCodeSendsParams{UserID: userID, Phone: phone})
	if err != nil {
		return err
	}
	if err := (codeSends{mine: sent.UserSends, mineOldest: sent.UserOldest, toAddress: sent.NumberSends,
		addressOldest: sent.NumberOldest, last: sent.UserLast}).limit(); err != nil {
		return err
	}
	id, err := qtx.InsertPhoneVerification(ctx, dbgen.InsertPhoneVerificationParams{
		UserID:    userID,
		Phone:     phone,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	})
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, who.event("phone.verification_started", userID,
		map[string]any{"phone": maskPhone(phone)})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return s.withdrawUndelivered(ctx, s.q.DeletePhoneVerification, id, s.sender.Send(ctx, notifier.Message{
		Channel: "sms",
		To:      phone,
		Body:    fmt.Sprintf("Your Qeet verification code is %s", code),
	}))
}

// canSendSMS refuses a code to phone unless it is in E.164 form, a provider
// can deliver SMS, and the plan of tenantID (nil: refused) includes SMS.
func (s *Service) canSendSMS(ctx context.Context, phone string, tenantID *uuid.UUID) error {
	if !e164.MatchString(phone) {
		return errVerifyPhoneInvalid
	}
	if s.deliverable != nil && !s.deliverable("sms") {
		return errs.ErrVerifyDeliveryUnavailable.WithMetadata(map[string]any{"channel": "sms"})
	}
	if s.plan == nil {
		return nil
	}
	refused := errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": smsFeature})
	if tenantID == nil {
		return refused
	}
	ok, err := s.plan.FeatureAllowed(ctx, *tenantID, smsFeature)
	if err != nil {
		return err
	}
	if !ok {
		return refused
	}
	return nil
}

// smsFeature is the plan feature that pays for SMS codes, MFA's and these alike.
const smsFeature = "sms_mfa"

// maskPhone keeps a number's last three digits, as audited: "*********567".
func maskPhone(phone string) string {
	if len(phone) <= 3 {
		return phone
	}
	return strings.Repeat("*", len(phone)-3) + phone[len(phone)-3:]
}

// ConfirmPhone verifies the user's phone number with the code sent to it,
// recorded as who's; a refused code is recorded as phone.verification_failed.
func (s *Service) ConfirmPhone(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	err := s.confirmPhone(ctx, userID, code, who)
	return s.auditRefusal(ctx, "phone.verification_failed", userID, map[string]any{}, who, err)
}

func (s *Service) confirmPhone(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	row, err := newestPhoneCode(ctx, tx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrVerifyCodeInvalid
		}
		return err
	}
	failed, err := s.q.WithTx(tx).PhoneCodeFailures(ctx, userID)
	if err != nil {
		return err
	}
	if err := chargeFailure(ctx, tx, "phone_verifications", row, code, guessBudget{failures: int(failed.Failures), oldest: failed.Oldest}); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).MarkPhoneVerificationUsed(ctx, row.id); err != nil {
		return err
	}
	// Persist the verified number itself (not just the timestamp) so downstream
	// SMS/OTP has a number to use and the account isn't left "verified" with a
	// NULL phone.
	if err := s.q.WithTx(tx).SetUserVerifiedPhone(ctx, dbgen.SetUserVerifiedPhoneParams{
		Phone:  &row.value,
		UserID: userID,
	}); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, who.event("phone.verified", userID,
		map[string]any{"phone": maskPhone(row.value), "proof": "sms_code"})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
