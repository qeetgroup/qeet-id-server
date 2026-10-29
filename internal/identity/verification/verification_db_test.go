//go:build integration

package verification

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestEmailVerification checks that the code mailed to the address on file
// verifies it, that a wrong code doesn't, and that the code works once.
func TestEmailVerification(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, TenantID: &tenant}
	verified := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND email_verified_at IS NOT NULL`, a.ID)
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
// wrong code and the right one are each recorded in the organisation the
// request came from, with the number masked.
func TestPhoneVerificationIsAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, TenantID: &tenant}
	const phone = "+14155550142"
	recorded := func(action string) []map[string]any {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata FROM audit.events
			WHERE tenant_id = $1 AND action = $2 AND resource_id = $3 AND actor_user_id = $3`, tenant, action, a.ID)
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
