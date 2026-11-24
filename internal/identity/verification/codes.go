package verification

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// latestCode is the newest outstanding verification row for a user, together
// with the hash of the code it was issued for.
type latestCode struct {
	id        uuid.UUID  // the row ID
	codeHash  string     // hash of the code
	value     string     // the email or phone carried on the row
	expiresAt time.Time  // when the code expires
	usedAt    *time.Time // when it was used; nil if unused
	attempts  int        // wrong guesses so far
	phone     bool       // a phone code, not an email code
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

// errVerifyFailuresPerHour refuses a confirm once the hour's guesses are spent.
var errVerifyFailuresPerHour = ErrVerifyAttemptsExceeded.WithMessage("Too many incorrect codes. Try again later.")

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
	return ErrVerifyCodeSendLimited.WithMetadata(map[string]any{"retry_after": retryAfter(wait)})
}

// matches reports whether the submitted code is the one this row was issued
// for, compared in constant time so a wrong code can't be recovered by timing.
func (l latestCode) matches(code string) bool {
	return subtle.ConstantTimeCompare([]byte(codes.Hash(code)), []byte(l.codeHash)) == 1
}

// recordFailedAttempt charges one guess against row in tx and reports whether
// that exhausted the budget, retiring the code on the guess that hits the cap.
// The caller must commit even though it then returns an error, or the count is
// lost and the budget is unlimited.
func recordFailedAttempt(ctx context.Context, tx pgx.Tx, row latestCode) (bool, error) {
	q := dbgen.New(tx)
	if row.phone {
		return q.ChargePhoneCodeGuess(ctx, dbgen.ChargePhoneCodeGuessParams{MaxAttempts: maxVerificationAttempts, ID: row.id})
	}
	return q.ChargeEmailCodeGuess(ctx, dbgen.ChargeEmailCodeGuessParams{MaxAttempts: maxVerificationAttempts, ID: row.id})
}

// chargeFailure runs the shared checks and, when the submitted code is wrong,
// persists the failed attempt before returning. It commits the transaction on
// that path so the count survives the caller's deferred rollback. A spent
// budget refuses even the right code, as a retired code does.
func chargeFailure(ctx context.Context, tx pgx.Tx, row latestCode, code string, budget guessBudget) error {
	if err := budget.spent(); err != nil {
		return err
	}
	err := checkUsable(row, code)
	if !errors.Is(err, ErrVerifyCodeInvalid) {
		// Expired, already used, or budget already gone: nothing to charge, and
		// a correct code (err == nil) falls through to the caller's success path.
		return err
	}
	exhausted, updErr := recordFailedAttempt(ctx, tx, row)
	if updErr != nil {
		return updErr
	}
	if cmtErr := tx.Commit(ctx); cmtErr != nil {
		return cmtErr
	}
	if exhausted {
		return ErrVerifyAttemptsExceeded
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
		return ErrVerifyAttemptsExceeded
	}
	// A stale code (superseded by a resend) and a plain wrong code are the same
	// thing to the caller: this is not the code we are waiting on.
	if !l.matches(code) {
		return ErrVerifyCodeInvalid
	}
	if l.usedAt != nil {
		return ErrVerifyCodeUsed
	}
	if time.Now().After(l.expiresAt) {
		return ErrVerifyCodeExpired
	}
	return nil
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

// auditRefusal records a refused confirm (a wrong, stale, used or exhausted
// code) as action, with metadata and the reason, in its own transaction since
// the confirm's own has ended. Any other error, and success, pass through.
func (s *Service) auditRefusal(ctx context.Context, action string, userID uuid.UUID, metadata map[string]any, who Requester, err error) error {
	e := errs.As(err)
	if e == nil || !isCodeRefusal(err) {
		return err
	}
	metadata["reason"] = e.Code
	if aerr := audit.RecordAlone(ctx, s.pool, who.event(action, userID, metadata)); aerr != nil {
		return aerr
	}
	return err
}

// isCodeRefusal reports whether err is one of the answers to a bad code.
func isCodeRefusal(err error) bool {
	return errors.Is(err, ErrVerifyCodeInvalid) || errors.Is(err, ErrVerifyCodeExpired) ||
		errors.Is(err, ErrVerifyCodeUsed) || errors.Is(err, ErrVerifyAttemptsExceeded)
}
