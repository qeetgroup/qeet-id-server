//go:build integration

package verification

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

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
	svc := newService(t, mail)
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
				if err := flow.confirm(a, wrongCode(code), who); !errors.Is(err, ErrVerifyCodeInvalid) && !errors.Is(err, ErrVerifyAttemptsExceeded) {
					t.Fatalf("%s: a wrong code: %v, want it refused", name, err)
				}
			}
		}
		if err := flow.confirm(a, code, who); !errors.Is(err, ErrVerifyAttemptsExceeded) {
			t.Errorf("%s: the right code after ten wrong guesses over three codes: %v, want %v", name, err, ErrVerifyAttemptsExceeded)
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
	svc := newService(t, mail)
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
				if !errors.Is(err, ErrVerifyCodeSendLimited) {
					t.Errorf("%s: a sixth code in the hour from a sixth account: %v, want %v", name, err, ErrVerifyCodeSendLimited)
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
	if err := svc.StartEmail(ctx, target.ID, "", who); !errors.Is(err, ErrVerifyCodeSendLimited) {
		t.Errorf("a sixth code to the address in the hour, to verify it: %v, want %v", err, ErrVerifyCodeSendLimited)
	}
}

// failingSender is a notifier.Sender whose provider refuses every message; it
// keeps them so a test can read the code that was never delivered.
type failingSender struct {
	mu   sync.Mutex
	sent []notifier.Message
}

// TestUndeliveredCodeIsWithdrawn checks that a code the provider refused is
// withdrawn, so even its right value proves nothing, in every flow, and that
// it still replaces the code sent before it.
func TestUndeliveredCodeIsWithdrawn(t *testing.T) {
	ctx := dbtest.Context(t)
	mail, failing := &dbtest.Mailbox{}, &failingSender{}
	delivering, refusing := codeFlows(ctx, newService(t, mail)), codeFlows(ctx, newService(t, failing))
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
		if err := flow.confirm(a, undelivered, who); !errors.Is(err, ErrVerifyCodeInvalid) {
			t.Errorf("%s: the undelivered code: %v, want %v", name, err, ErrVerifyCodeInvalid)
		}
		if err := flow.confirm(a, earlier, who); err == nil {
			t.Errorf("%s: the code the undelivered one replaced still works", name)
		}
	}
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
