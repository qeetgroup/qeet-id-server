//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// smallPool builds a pool with a hard connection ceiling, so a code path that
// needs two connections at once starves instead of merely slowing down.
func smallPool(t *testing.T, ctx context.Context, maxConns int32) *pgxpool.Pool {
	t.Helper()
	if testDSN == "" {
		t.Skip("no test DSN available")
	}
	cfg, err := pgxpool.ParseConfig(testDSN)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open constrained pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// enrollConfirmedTOTP gets a user to a confirmed TOTP factor on the given pool
// and returns the shared secret.
func enrollConfirmedTOTP(t *testing.T, ctx context.Context, pool *pgxpool.Pool, svc *mfa.Service, userID uuid.UUID) string {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin enrollment: %v", err)
	}
	enrollment, err := svc.StartEnroll(ctx, tx, userID, "pool@example.com")
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("start enrollment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit enrollment: %v", err)
	}

	code, err := totp.Code(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	attempt, err := svc.ReserveAttempt(ctx, userID, mfa.PurposeTOTPEnroll)
	if err != nil {
		t.Fatalf("reserve enrollment attempt: %v", err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin confirmation: %v", err)
	}
	if _, err := svc.ConfirmEnroll(ctx, tx, attempt, code); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("confirm enrollment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit confirmation: %v", err)
	}
	return enrollment.Secret
}

// verifyOnPool mirrors the handler ordering exactly: reserve the attempt slot,
// then open the transaction the verification runs in. The ordering is the whole
// point of the test — reserving underneath the transaction is what deadlocked.
func verifyOnPool(ctx context.Context, pool *pgxpool.Pool, svc *mfa.Service, userID uuid.UUID, code string) error {
	attempt, err := svc.ReserveAttempt(ctx, userID, mfa.PurposeFactorVerify)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := svc.Verify(ctx, tx, attempt, code); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TestMFAVerifyDoesNotExhaustPoolUnderConcurrency is the regression test for
// the attempt-budget deadlock.
//
// The budget reservation runs in its own transaction so a rejected code still
// costs an attempt after the caller rolls back. When that reservation happened
// *inside* the caller's transaction, every in-flight verification held one
// connection and then asked the same pool for a second. Once concurrency
// reached the pool ceiling, every request was holding a connection while
// waiting for one, and nothing could make progress until request deadlines
// fired.
//
// The pool here is capped at 2 while 8 verifications run at once. Under the old
// ordering that deadlocks and every goroutine returns a timeout. Under the
// current ordering each request needs at most one connection at a time, so they
// serialise and all complete well inside the deadline.
func TestMFAVerifyDoesNotExhaustPoolUnderConcurrency(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	const maxConns = 2
	const contenders = 8

	pool := smallPool(t, ctx, maxConns)
	tenantID := createTenant(t, ctx, uniqueSlug("mfa-pool"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := mfa.NewService(pool, "qeet-test", notifier.LogSender{}, "")
	svc.SetCipher(testEnvelope(t))
	enrollConfirmedTOTP(t, ctx, pool, svc, userID)

	// A deadline far longer than the work needs, but far shorter than the test
	// timeout: if the pool deadlocks, this is what the goroutines trip on.
	deadlined, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	start := make(chan struct{})
	errCh := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errCh <- verifyOnPool(deadlined, pool, svc, userID, "000000")
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() { wait.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatal("concurrent MFA verifications did not finish: the connection pool is deadlocked")
	}
	close(errCh)

	// Every attempt used a wrong code, so each must come back as a rejected
	// credential or an exhausted budget — never a pool timeout.
	rejected, exhausted := 0, 0
	for err := range errCh {
		switch {
		case errors.Is(err, errs.ErrMFACodeInvalid):
			rejected++
		case errors.Is(err, errs.ErrMFAAttemptsExceeded):
			exhausted++
		case err == nil:
			t.Error("a wrong TOTP code must not verify")
		default:
			t.Errorf("unexpected error (pool starvation would surface here): %v", err)
		}
	}
	if rejected+exhausted != contenders {
		t.Fatalf("accounted %d of %d attempts (rejected=%d exhausted=%d)",
			rejected+exhausted, contenders, rejected, exhausted)
	}
	// The budget is 5, so at most 5 of the 8 can be counted as real guesses and
	// the rest must be turned away. This also proves the reservation is
	// genuinely atomic: without the row lock, concurrent readers would each see
	// a stale counter and more than 5 would slip through.
	if rejected > 5 {
		t.Errorf("counted %d guesses against a budget of 5 — reservation is not atomic", rejected)
	}
	if exhausted == 0 {
		t.Errorf("no attempt was turned away; budget was not enforced under concurrency")
	}

	var failed int16
	var lockedUntil *time.Time
	if err := pool.QueryRow(ctx, `
		SELECT failed_attempts, locked_until FROM auth.mfa_attempt_budgets
		WHERE user_id = $1 AND purpose = $2
	`, userID, mfa.PurposeFactorVerify).Scan(&failed, &lockedUntil); err != nil {
		t.Fatalf("read budget: %v", err)
	}
	if failed != 5 {
		t.Errorf("failed_attempts = %d, want exactly 5 (the budget ceiling)", failed)
	}
	if lockedUntil == nil {
		t.Error("exhausting the budget must set locked_until")
	}
}

// TestMFAAttemptAccountingAcrossOutcomes pins the accounting rules that the
// reserve/refund split has to preserve: a rejected code costs an attempt even
// though the caller rolls back, an infrastructure failure gives the attempt
// back, and a success clears the budget entirely.
func TestMFAAttemptAccountingAcrossOutcomes(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa-acct"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, "")
	svc.SetCipher(testEnvelope(t))
	secret := enrollConfirmedTOTP(t, ctx, testPool, svc, userID)

	budget := func() int16 {
		t.Helper()
		var failed int16
		err := testPool.QueryRow(ctx, `
			SELECT failed_attempts FROM auth.mfa_attempt_budgets
			WHERE user_id = $1 AND purpose = $2
		`, userID, mfa.PurposeFactorVerify).Scan(&failed)
		if err != nil {
			return 0 // no row: the budget is clear
		}
		return failed
	}

	// A rejected code must survive the caller's rollback. This is exactly why
	// the reservation gets its own transaction.
	if err := verifyOnPool(ctx, testPool, svc, userID, "000000"); !errors.Is(err, errs.ErrMFACodeInvalid) {
		t.Fatalf("wrong code error = %v, want invalid", err)
	}
	if got := budget(); got != 1 {
		t.Fatalf("after one rejected code failed_attempts = %d, want 1", got)
	}

	// An infrastructure failure after reservation must hand the slot back, so a
	// database blip does not spend the user's budget.
	attempt, err := svc.ReserveAttempt(ctx, userID, mfa.PurposeFactorVerify)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if got := budget(); got != 2 {
		t.Fatalf("reservation should have counted: failed_attempts = %d, want 2", got)
	}
	svc.RefundAttempt(ctx, attempt)
	if got := budget(); got != 1 {
		t.Fatalf("after refund failed_attempts = %d, want 1", got)
	}

	// A correct code clears the budget completely.
	code, err := totp.Code(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	if err := verifyOnPool(ctx, testPool, svc, userID, code); err != nil {
		t.Fatalf("correct code error = %v, want success", err)
	}
	if got := budget(); got != 0 {
		t.Fatalf("a successful verification must clear the budget, got %d", got)
	}

	// A cancelled request must not silently consume the budget either: the
	// reservation fails outright rather than counting a guess the user never
	// got to make.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.ReserveAttempt(cancelled, userID, mfa.PurposeFactorVerify); err == nil {
		t.Error("reserving on a cancelled context should fail")
	}
	if got := budget(); got != 0 {
		t.Errorf("a cancelled reservation must not count: failed_attempts = %d, want 0", got)
	}
}
