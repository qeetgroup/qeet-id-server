//go:build integration

package verification

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestEmailVerification checks that the code mailed to the address on file
// verifies it, that a wrong code doesn't, and that the code works once.
func TestEmailVerification(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, OrganizationID: &organization}
	verified := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email_verified_at IS NOT NULL`, a.ID)
	}

	if err := svc.StartEmail(ctx, a.ID, "", who); err != nil {
		t.Fatalf("start: %v", err)
	}
	msg := mail.Last(t)
	code := regexp.MustCompile(`\b\d{6}\b`).FindString(msg.Body)
	if msg.To != a.Email || code == "" {
		t.Fatalf("verification mail to %s with body %q; want a code to %s", msg.To, msg.Body, a.Email)
	}

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if err := svc.ConfirmEmail(ctx, a.ID, wrong, who); !errors.Is(err, errs.ErrVerifyCodeInvalid) {
		t.Errorf("wrong code: %v, want %v", err, errs.ErrVerifyCodeInvalid)
	}
	if verified() != 0 {
		t.Fatal("a wrong code verified the address")
	}
	if err := svc.ConfirmEmail(ctx, a.ID, code, who); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if verified() != 1 {
		t.Fatal("the right code did not verify the address")
	}
	if err := svc.ConfirmEmail(ctx, a.ID, code, who); !errors.Is(err, errs.ErrVerifyCodeUsed) {
		t.Errorf("second use of the code: %v, want %v", err, errs.ErrVerifyCodeUsed)
	}
}

// TestPhoneVerificationIsAudited checks that sending a code to a number, a
// wrong code and the right one are each recorded in the organization the
// request came from, with the number masked.
func TestPhoneVerificationIsAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, OrganizationID: &organization}
	const phone = "+14155550142"
	recorded := func(action string) []map[string]any {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND resource_id = $3 AND actor_user_id = $3`, organization, action, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var m map[string]any
			if err := rows.Scan(&m); err != nil {
				t.Fatal(err)
			}
			out = append(out, m)
		}
		return out
	}

	if err := svc.StartPhone(ctx, a.ID, phone, who); err != nil {
		t.Fatalf("start: %v", err)
	}
	msg := mail.Last(t)
	code := regexp.MustCompile(`\b\d{6}\b`).FindString(msg.Body)
	if msg.Channel != "sms" || msg.To != phone || code == "" {
		t.Fatalf("code sent %+v; want an SMS code to %s", msg, phone)
	}
	if got := recorded("phone.verification_started"); len(got) != 1 || got[0]["phone"] != "*********142" {
		t.Errorf("phone.verification_started records %v, want one with the number masked", got)
	}

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if err := svc.ConfirmPhone(ctx, a.ID, wrong, who); !errors.Is(err, errs.ErrVerifyCodeInvalid) {
		t.Fatalf("wrong code: %v, want %v", err, errs.ErrVerifyCodeInvalid)
	}
	if got := recorded("phone.verification_failed"); len(got) != 1 || got[0]["reason"] != errs.CodeVerifyCodeInvalid {
		t.Errorf("phone.verification_failed records %v, want one for the wrong code", got)
	}
	if err := svc.ConfirmPhone(ctx, a.ID, code, who); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got := recorded("phone.verified"); len(got) != 1 || got[0]["phone"] != "*********142" || got[0]["proof"] != "sms_code" {
		t.Errorf("phone.verified records %v, want one with the number masked", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE resource_id = $1 AND strpos(metadata::text, $2) > 0`, a.ID, phone[2:]); n != 0 {
		t.Errorf("%d audit records hold the whole number", n)
	}
}

// codeIn returns the code of digits digits in body, failing t without one.
func codeIn(t *testing.T, body string, digits int) string {
	t.Helper()
	code := regexp.MustCompile(`\b\d{` + strconv.Itoa(digits) + `}\b`).FindString(body)
	if code == "" {
		t.Fatalf("no %d-digit code in %q", digits, body)
	}
	return code
}

// wrongCode returns a code of code's length that isn't code.
func wrongCode(code string) string {
	b := []byte(code)
	b[len(b)-1] = '0' + (b[len(b)-1]-'0'+1)%10
	return string(b)
}

// age moves userID's codes in table back by d, as if sent d earlier.
func age(t *testing.T, table string, userID uuid.UUID, d time.Duration) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(context.Background(), `UPDATE account.`+table+`
		SET created_at = created_at - $2::interval, expires_at = expires_at - $2::interval WHERE user_id = $1`,
		userID, d.String()); err != nil {
		t.Fatal(err)
	}
}

// phoneNumber returns a random E.164 number.
func phoneNumber() string { return fmt.Sprintf("+1415%07d", rand.IntN(10_000_000)) }

// codeFlow is one way to prove an address with a code.
type codeFlow struct {
	table   string
	digits  int
	start   func(a dbtest.Account, who Requester) error
	confirm func(a dbtest.Account, code string, who Requester) error
}

// codeFlows returns the email, email-change and phone flows of svc.
func codeFlows(ctx context.Context, svc *Service) map[string]codeFlow {
	return map[string]codeFlow{
		"verify_email": {"email_verifications", 6,
			func(a dbtest.Account, who Requester) error { return svc.StartEmail(ctx, a.ID, "", who) },
			func(a dbtest.Account, code string, who Requester) error {
				return svc.ConfirmEmail(ctx, a.ID, code, who)
			}},
		"change_email": {"email_verifications", 8,
			func(a dbtest.Account, who Requester) error {
				return svc.StartEmailChange(ctx, a.ID, dbtest.Unique("moved")+"@example.test", who)
			},
			func(a dbtest.Account, code string, who Requester) error {
				_, err := svc.ConfirmEmailChange(ctx, a.ID, code, who)
				return err
			}},
		"phone": {"phone_verifications", 6,
			func(a dbtest.Account, who Requester) error { return svc.StartPhone(ctx, a.ID, phoneNumber(), who) },
			func(a dbtest.Account, code string, who Requester) error {
				return svc.ConfirmPhone(ctx, a.ID, code, who)
			}},
	}
}

// TestGuessBudgetSpansResends checks that ten wrong guesses in an hour, over
// any number of codes asked for in between, refuse even the right code until
// the hour has passed, for each flow on its own.
func TestGuessBudgetSpansResends(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	organization := dbtest.Organization(t)
	for name, flow := range codeFlows(ctx, svc) {
		a := dbtest.User(t, organization, organization)
		who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, OrganizationID: &organization}
		var code string
		for _, guesses := range []int{4, 4, 2} {
			age(t, flow.table, a.ID, time.Minute)
			if err := flow.start(a, who); err != nil {
				t.Fatalf("%s: start: %v", name, err)
			}
			code = codeIn(t, mail.Last(t).Body, flow.digits)
			for range guesses {
				if err := flow.confirm(a, wrongCode(code), who); !errors.Is(err, errs.ErrVerifyCodeInvalid) && !errors.Is(err, errs.ErrVerifyAttemptsExceeded) {
					t.Fatalf("%s: a wrong code: %v, want it refused", name, err)
				}
			}
		}
		if err := flow.confirm(a, code, who); !errors.Is(err, errs.ErrVerifyAttemptsExceeded) {
			t.Errorf("%s: the right code after ten wrong guesses over three codes: %v, want %v", name, err, errs.ErrVerifyAttemptsExceeded)
		}

		age(t, flow.table, a.ID, time.Hour+time.Minute)
		if err := flow.start(a, who); err != nil {
			t.Fatalf("%s: start an hour later: %v", name, err)
		}
		if err := flow.confirm(a, codeIn(t, mail.Last(t).Body, flow.digits), who); err != nil {
			t.Errorf("%s: the right code an hour later: %v, want it accepted", name, err)
		}
	}
}

// TestCodesToOneAddressAreCappedPerHour checks that at most five codes an hour
// go to one address over every account and both email flows, an address
// another account holds included (it gets a notice each time), and that the
// limit lifts once the hour has passed.
func TestCodesToOneAddressAreCappedPerHour(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	organization := dbtest.Organization(t)
	target := dbtest.UserAt(t, dbtest.Unique("target")+"@example.test", organization, organization)
	free := dbtest.Unique("free") + "@example.test"
	for name, address := range map[string]string{"an address another account holds": target.Email, "a free address": free} {
		sent := mail.Len()
		var last dbtest.Account
		for i := range 6 {
			last = dbtest.User(t, organization, organization)
			who := Requester{Actor: audit.Actor{UserID: &last.ID, Type: "user"}, OrganizationID: &organization}
			err := svc.StartEmailChange(ctx, last.ID, address, who)
			if i < 5 && err != nil {
				t.Fatalf("%s: send %d: %v", name, i+1, err)
			}
			if i == 5 {
				if !errors.Is(err, errs.ErrVerifyCodeSendLimited) {
					t.Errorf("%s: a sixth code in the hour from a sixth account: %v, want %v", name, err, errs.ErrVerifyCodeSendLimited)
				} else if after, _ := errs.As(err).Metadata["retry_after"].(int); after <= 0 || after > 3600 {
					t.Errorf("%s: retry_after %v, want within the hour", name, errs.As(err).Metadata["retry_after"])
				}
			}
		}
		if n := mail.Len() - sent; n != 5 {
			t.Errorf("%s: %d messages sent, want 5", name, n)
		}
		if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.email_verifications SET created_at = created_at - INTERVAL '61 minutes'
			WHERE lower(email) = lower($1)`, address); err != nil {
			t.Fatal(err)
		}
		who := Requester{Actor: audit.Actor{UserID: &last.ID, Type: "user"}, OrganizationID: &organization}
		if err := svc.StartEmailChange(ctx, last.ID, address, who); err != nil {
			t.Errorf("%s: a code an hour later: %v", name, err)
		}
	}
	// The address's own account verifying it counts against the same limit.
	who := Requester{Actor: audit.Actor{UserID: &target.ID, Type: "user"}, OrganizationID: &organization}
	for range 4 {
		if err := svc.StartEmail(ctx, target.ID, "", who); err != nil {
			t.Fatalf("verify the address on file: %v", err)
		}
	}
	if err := svc.StartEmail(ctx, target.ID, "", who); !errors.Is(err, errs.ErrVerifyCodeSendLimited) {
		t.Errorf("a sixth code to the address in the hour, to verify it: %v, want %v", err, errs.ErrVerifyCodeSendLimited)
	}
}

// failingSender is a notifier.Sender whose provider refuses every message; it
// keeps them so a test can read the code that was never delivered.
type failingSender struct {
	mu   sync.Mutex
	sent []notifier.Message
}

func (f *failingSender) Send(_ context.Context, m notifier.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return errors.New("provider refused the message")
}

func (f *failingSender) last() notifier.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[len(f.sent)-1]
}

// TestUndeliveredCodeIsWithdrawn checks that a code the provider refused is
// withdrawn, so even its right value proves nothing, in every flow, and that
// it still replaces the code sent before it.
func TestUndeliveredCodeIsWithdrawn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail, failing := &dbtest.Mailbox{}, &failingSender{}
	delivering, refusing := codeFlows(ctx, NewService(pool, mail, 10*time.Minute)), codeFlows(ctx, NewService(pool, failing, 10*time.Minute))
	organization := dbtest.Organization(t)
	for name, flow := range refusing {
		a := dbtest.User(t, organization, organization)
		who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, OrganizationID: &organization}
		if err := delivering[name].start(a, who); err != nil {
			t.Fatalf("%s: start: %v", name, err)
		}
		earlier := codeIn(t, mail.Last(t).Body, flow.digits)
		age(t, flow.table, a.ID, time.Minute)
		if err := flow.start(a, who); err == nil {
			t.Fatalf("%s: a code the provider refused was reported sent", name)
		}
		undelivered := codeIn(t, failing.last().Body, flow.digits)
		if err := flow.confirm(a, undelivered, who); !errors.Is(err, errs.ErrVerifyCodeInvalid) {
			t.Errorf("%s: the undelivered code: %v, want %v", name, err, errs.ErrVerifyCodeInvalid)
		}
		if err := flow.confirm(a, earlier, who); err == nil {
			t.Errorf("%s: the code the undelivered one replaced still works", name)
		}
	}
}

// TestPhoneVerificationSendsAreCapped checks that phone codes follow the MFA
// SMS codes' limits: thirty seconds between a person's codes, ten an hour per
// person and five an hour per number over every account.
func TestPhoneVerificationSendsAreCapped(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	organization := dbtest.Organization(t)
	person := func() (dbtest.Account, Requester) {
		a := dbtest.User(t, organization, organization)
		return a, Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, OrganizationID: &organization}
	}
	limited := func(what string, err error, upTo int) {
		t.Helper()
		if !errors.Is(err, errs.ErrVerifyCodeSendLimited) {
			t.Errorf("%s: %v, want %v", what, err, errs.ErrVerifyCodeSendLimited)
		} else if after, _ := errs.As(err).Metadata["retry_after"].(int); after <= 0 || after > upTo {
			t.Errorf("%s: retry_after %v, want 1 to %d", what, errs.As(err).Metadata["retry_after"], upTo)
		}
	}

	a, who := person()
	if err := svc.StartPhone(ctx, a.ID, phoneNumber(), who); err != nil {
		t.Fatal(err)
	}
	limited("a second code at once", svc.StartPhone(ctx, a.ID, phoneNumber(), who), 30)
	for i := 2; i <= 10; i++ {
		age(t, "phone_verifications", a.ID, 31*time.Second)
		if err := svc.StartPhone(ctx, a.ID, phoneNumber(), who); err != nil {
			t.Fatalf("code %d in the hour: %v", i, err)
		}
	}
	age(t, "phone_verifications", a.ID, 31*time.Second)
	limited("an eleventh code in the hour", svc.StartPhone(ctx, a.ID, phoneNumber(), who), 3600)

	number := phoneNumber()
	for i := range 5 {
		b, who := person()
		if err := svc.StartPhone(ctx, b.ID, number, who); err != nil {
			t.Fatalf("code %d to the number: %v", i+1, err)
		}
	}
	c, who := person()
	limited("a sixth code to one number from a sixth account", svc.StartPhone(ctx, c.ID, number, who), 3600)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.phone_verifications WHERE phone = $1`, number); n != 5 {
		t.Errorf("%d codes stored for the number, want 5", n)
	}
}

// planGate allows a feature to the organizations in allowed only.
type planGate struct{ allowed map[uuid.UUID]bool }

func (p planGate) FeatureAllowed(_ context.Context, organizationID uuid.UUID, feature string) (bool, error) {
	return feature == "sms_mfa" && p.allowed[organizationID], nil
}

// TestPhoneVerificationNeedsSMSInThePlan checks that a phone code goes only to
// an E.164 number, from a session in an organization whose plan includes SMS,
// when a provider can deliver SMS; anything else is refused before a code is
// stored or sent.
func TestPhoneVerificationNeedsSMSInThePlan(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	paid, free := dbtest.Organization(t), dbtest.Organization(t)
	svc.SetPlan(planGate{allowed: map[uuid.UUID]bool{paid: true}})
	deliverable := true
	svc.SetDeliveryCheck(func(channel string) bool { return channel == "sms" && deliverable })
	a := dbtest.User(t, paid, paid, free)
	in := func(organization *uuid.UUID) Requester {
		return Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, OrganizationID: organization}
	}
	refused := func(what string, err error, want *errs.Error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", what, err, want)
		}
	}

	refused("from an organisation whose plan has no SMS", svc.StartPhone(ctx, a.ID, phoneNumber(), in(&free)), errs.ErrUpgradeRequired)
	refused("from a session in no organisation", svc.StartPhone(ctx, a.ID, phoneNumber(), in(nil)), errs.ErrUpgradeRequired)
	for _, number := range []string{"555-0100", "+0123456789", "14155550100", "+1 415 555 0100", "+1415555010012345"} {
		refused("to "+number, svc.StartPhone(ctx, a.ID, number, in(&paid)), errs.ErrValidationFailed)
	}
	deliverable = false
	refused("with no SMS provider", svc.StartPhone(ctx, a.ID, phoneNumber(), in(&paid)), errs.ErrVerifyDeliveryUnavailable)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.phone_verifications WHERE user_id = $1`, a.ID); n != 0 || mail.Len() != 0 {
		t.Fatalf("%d codes stored and %d sent for refused requests, want none", n, mail.Len())
	}
	deliverable = true
	if err := svc.StartPhone(ctx, a.ID, phoneNumber(), in(&paid)); err != nil {
		t.Errorf("from an organisation whose plan has SMS: %v", err)
	}
}
