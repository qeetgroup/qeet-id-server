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
