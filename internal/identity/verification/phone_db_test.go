//go:build integration

package verification

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPhoneVerificationIsAudited checks that sending a code to a number, a
// wrong code and the right one are each recorded in the organization the
// request came from, with the number masked.
func TestPhoneVerificationIsAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := newService(t, mail)
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
	if err := svc.ConfirmPhone(ctx, a.ID, wrong, who); !errors.Is(err, ErrVerifyCodeInvalid) {
		t.Fatalf("wrong code: %v, want %v", err, ErrVerifyCodeInvalid)
	}
	if got := recorded("phone.verification_failed"); len(got) != 1 || got[0]["reason"] != CodeVerifyCodeInvalid {
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

// TestPhoneVerificationSendsAreCapped checks that phone codes follow the MFA
// SMS codes' limits: thirty seconds between a person's codes, ten an hour per
// person and five an hour per number over every account.
func TestPhoneVerificationSendsAreCapped(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := newService(t, mail)
	organization := dbtest.Organization(t)
	person := func() (dbtest.Account, Requester) {
		a := dbtest.User(t, organization, organization)
		return a, Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, OrganizationID: &organization}
	}
	limited := func(what string, err error, upTo int) {
		t.Helper()
		if !errors.Is(err, ErrVerifyCodeSendLimited) {
			t.Errorf("%s: %v, want %v", what, err, ErrVerifyCodeSendLimited)
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

// TestPhoneVerificationNeedsSMSInThePlan checks that a phone code goes only to
// an E.164 number, from a session in an organization whose plan includes SMS,
// when a provider can deliver SMS; anything else is refused before a code is
// stored or sent.
func TestPhoneVerificationNeedsSMSInThePlan(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	paid, free := dbtest.Organization(t), dbtest.Organization(t)
	deliverable := true
	svc, err := NewService(dbtest.Pool(t), mail, 10*time.Minute, planGate{allowed: map[uuid.UUID]bool{paid: true}},
		func(channel string) bool { return channel == "sms" && deliverable })
	if err != nil {
		t.Fatal(err)
	}
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

	refused("from an organization whose plan has no SMS", svc.StartPhone(ctx, a.ID, phoneNumber(), in(&free)), errs.ErrUpgradeRequired)
	refused("from a session in no organization", svc.StartPhone(ctx, a.ID, phoneNumber(), in(nil)), errs.ErrUpgradeRequired)
	for _, number := range []string{"555-0100", "+0123456789", "14155550100", "+1 415 555 0100", "+1415555010012345"} {
		refused("to "+number, svc.StartPhone(ctx, a.ID, number, in(&paid)), errs.ErrValidationFailed)
	}
	deliverable = false
	refused("with no SMS provider", svc.StartPhone(ctx, a.ID, phoneNumber(), in(&paid)), ErrVerifyDeliveryUnavailable)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.phone_verifications WHERE user_id = $1`, a.ID); n != 0 || mail.Len() != 0 {
		t.Fatalf("%d codes stored and %d sent for refused requests, want none", n, mail.Len())
	}
	deliverable = true
	if err := svc.StartPhone(ctx, a.ID, phoneNumber(), in(&paid)); err != nil {
		t.Errorf("from an organization whose plan has SMS: %v", err)
	}
}

func (p planGate) FeatureAllowed(_ context.Context, organizationID uuid.UUID, feature string) (bool, error) {
	return feature == "sms_mfa" && p.allowed[organizationID], nil
}
