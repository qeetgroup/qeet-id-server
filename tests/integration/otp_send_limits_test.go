//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Sending email and SMS codes is limited to the pace of a person asking for
// one: a wait between codes to one factor, an hourly limit per person and per
// address or number, at most one live code per factor, a bound on how many
// factors one person may hold, the SMS plan applied at every send, and an
// audit entry for each code sent.

// allowNextCode moves a factor's codes a minute into the past, so the next
// code may be sent at once.
func allowNextCode(t *testing.T, ctx context.Context, factorID uuid.UUID) {
	t.Helper()
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_otp_codes SET created_at = created_at - INTERVAL '1 minute' WHERE factor_id = $1`, factorID); err != nil {
		t.Fatal(err)
	}
}

// otpFixture is a person with a confirmed email factor, and the codes sent.
type otpFixture struct {
	svc      *mfa.Service
	sender   *captureSender
	userID   uuid.UUID
	factorID uuid.UUID
	address  string
}

func newOTPFixture(t *testing.T, ctx context.Context) otpFixture {
	t.Helper()
	f := otpFixture{sender: &captureSender{}, address: uniqueSlug("codes") + "@example.com"}
	f.svc = mfa.NewService(testPool, "qeet-test", f.sender, "")
	f.svc.SetCipher(testEnvelope(t))
	f.userID = createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("codes")))
	var err error
	if f.factorID, err = f.svc.EnrollOTPStart(ctx, f.userID, nil, "email", f.address); err != nil {
		t.Fatal(err)
	}
	msg, _ := f.sender.last()
	if err := mfaEnrollOTPConfirm(ctx, f.svc, f.userID, f.factorID, sixDigits.FindString(msg.Body)); err != nil {
		t.Fatal(err)
	}
	return f
}

func retryAfter(t *testing.T, err error) int {
	t.Helper()
	if !errors.Is(err, errs.ErrMFACodeSendLimited) {
		t.Fatalf("want %s, got %v", errs.CodeMFACodeSendLimited, err)
	}
	secs, _ := errs.As(err).Metadata["retry_after"].(int)
	return secs
}

// TestCodeSendsWaitBetweenCodes: a second code to the same factor straight
// away is refused with the wait left; after the wait it goes.
func TestCodeSendsWaitBetweenCodes(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newOTPFixture(t, ctx)
	if secs := retryAfter(t, f.svc.ChallengeOTP(ctx, f.userID, nil, f.factorID)); secs < 1 || secs > 30 {
		t.Fatalf("retry_after = %d, want within the 30s wait", secs)
	}
	allowNextCode(t, ctx, f.factorID)
	if err := f.svc.ChallengeOTP(ctx, f.userID, nil, f.factorID); err != nil {
		t.Fatalf("after the wait a code must go: %v", err)
	}
}

// TestNewCodeReplacesTheLastOne: once a new code is sent, the earlier unused
// one stops working.
func TestNewCodeReplacesTheLastOne(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newOTPFixture(t, ctx)
	allowNextCode(t, ctx, f.factorID)
	if err := f.svc.ChallengeOTP(ctx, f.userID, nil, f.factorID); err != nil {
		t.Fatal(err)
	}
	first, _ := f.sender.last()
	allowNextCode(t, ctx, f.factorID)
	if err := f.svc.ChallengeOTP(ctx, f.userID, nil, f.factorID); err != nil {
		t.Fatal(err)
	}
	second, _ := f.sender.last()
	if ok, _ := mfaVerifyOTP(ctx, f.svc, f.userID, sixDigits.FindString(first.Body)); ok {
		t.Fatal("an earlier code must stop working once a new one is sent")
	}
	if ok, err := mfaVerifyOTP(ctx, f.svc, f.userID, sixDigits.FindString(second.Body)); err != nil || !ok {
		t.Fatalf("the latest code must work: %v %v", ok, err)
	}
}

// TestCodeSendsHourlyLimits: past ten codes in an hour for one person, or five
// to one address over every account, another is refused until the oldest
// counted code is an hour old.
func TestCodeSendsHourlyLimits(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newOTPFixture(t, ctx)
	sentAgo := func(factorID uuid.UUID, n int, minutes int) {
		for i := 0; i < n; i++ {
			if _, err := testPool.Exec(ctx, `
				INSERT INTO auth.mfa_otp_codes (factor_id, code_hash, expires_at, created_at)
				VALUES ($1, $2, NOW(), NOW() - make_interval(mins => $3))`, factorID, uuid.NewString(), minutes); err != nil {
				t.Fatal(err)
			}
		}
	}

	allowNextCode(t, ctx, f.factorID)
	sentAgo(f.factorID, 9, 50) // with the enrolment code: ten in the hour
	if secs := retryAfter(t, f.svc.ChallengeOTP(ctx, f.userID, nil, f.factorID)); secs < 9*60 || secs > 11*60 {
		t.Fatalf("retry_after = %ds, want about ten minutes, when the oldest counted code turns an hour old", secs)
	}

	// Another account holding the same address shares its limit.
	g := newOTPFixture(t, ctx)
	other := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("codes-other")))
	factorID, err := g.svc.EnrollOTPStart(ctx, other, nil, "email", g.address)
	if err != nil {
		t.Fatalf("a second account's first code to the address: %v", err)
	}
	sentAgo(factorID, 3, 40) // five to the address in the hour
	allowNextCode(t, ctx, g.factorID)
	if secs := retryAfter(t, g.svc.ChallengeOTP(ctx, g.userID, nil, g.factorID)); secs < 15*60 {
		t.Fatalf("retry_after = %ds, want about twenty minutes, the address's hourly limit", secs)
	}
}

// TestFactorCountIsBounded: a person may hold five email and SMS factors;
// asking for a code to one already held still works at the limit.
func TestFactorCountIsBounded(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newOTPFixture(t, ctx)
	for i := 0; i < 4; i++ {
		if _, err := f.svc.EnrollOTPStart(ctx, f.userID, nil, "email", uniqueSlug("more")+"@example.com"); err != nil {
			t.Fatalf("factor %d: %v", i+2, err)
		}
	}
	if _, err := f.svc.EnrollOTPStart(ctx, f.userID, nil, "email", uniqueSlug("sixth")+"@example.com"); !errors.Is(err, errs.ErrMFAFactorLimit) {
		t.Fatalf("a sixth factor: %v, want %s", err, errs.CodeMFAFactorLimit)
	}
	allowNextCode(t, ctx, f.factorID)
	if _, err := f.svc.EnrollOTPStart(ctx, f.userID, nil, "email", f.address); err != nil {
		t.Fatalf("a code to a factor already held, at the limit: %v", err)
	}
}

type smsPlan struct{ allowed bool }

func (p smsPlan) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) {
	return p.allowed, nil
}

// TestSMSCodesFollowThePlan: an SMS code at sign-in or step-up is refused on
// a plan without SMS, and always without an organisation.
func TestSMSCodesFollowThePlan(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := mfa.NewService(testPool, "qeet-test", &captureSender{}, "")
	svc.SetCipher(testEnvelope(t))
	tenantID := createTenant(t, ctx, uniqueSlug("sms"))
	userID := createUserInTenant(t, ctx, tenantID)
	var factorID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.mfa_otp_factors (user_id, channel, destination, verified_at)
		VALUES ($1, 'sms', '+15550100', NOW()) RETURNING id`, userID).Scan(&factorID); err != nil {
		t.Fatal(err)
	}
	svc.SetPlan(smsPlan{allowed: false})
	if err := svc.SendLoginCode(ctx, userID, &tenantID, factorID); !errors.Is(err, errs.ErrUpgradeRequired) {
		t.Fatalf("an SMS sign-in code on a plan without SMS: %v, want upgrade_required", err)
	}
	svc.SetPlan(smsPlan{allowed: true})
	if err := svc.SendLoginCode(ctx, userID, nil, factorID); !errors.Is(err, errs.ErrUpgradeRequired) {
		t.Fatalf("an SMS code with no organisation: %v, want upgrade_required", err)
	}
	if err := svc.ChallengeOTP(ctx, userID, &tenantID, factorID); err != nil {
		t.Fatalf("an SMS code on a plan with SMS: %v", err)
	}
}

// TestCodeSendsAreAudited: each code sent is audited with its factor, purpose
// and the destination masked; expired codes are removed by the clean-up.
func TestCodeSendsAreAudited(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newOTPFixture(t, ctx)
	var destination, purpose string
	if err := testPool.QueryRow(ctx, `
		SELECT metadata->>'destination', metadata->>'purpose' FROM audit.events
		WHERE actor_user_id = $1 AND action = 'mfa.otp_sent' AND resource_id = $2`, f.userID, f.factorID).
		Scan(&destination, &purpose); err != nil {
		t.Fatalf("no audit entry for the code sent: %v", err)
	}
	if destination == f.address || destination == "" || purpose != "enrollment" {
		t.Fatalf("audited destination %q purpose %q, want masked and enrollment", destination, purpose)
	}

	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_otp_codes SET expires_at = NOW() - INTERVAL '2 days' WHERE factor_id = $1`, f.factorID); err != nil {
		t.Fatal(err)
	}
	if n, err := mfa.PurgeExpiredOTPCodes(ctx, testPool, mfa.OTPCodeRetention); err != nil || n < 1 {
		t.Fatalf("clean-up removed %d: %v", n, err)
	}
}
