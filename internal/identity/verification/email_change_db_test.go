//go:build integration

package verification

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestEmailChangeToAddressInUse checks that asking to move to an address
// another account holds is answered as a free address is, that the address is
// sent a notice rather than a code, and that the account keeps its address.
func TestEmailChangeToAddressInUse(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(dbtest.Pool(t), mail, 10*time.Minute)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	holder := dbtest.User(t, tenant, tenant)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, TenantID: &tenant}
	as := dbtest.Serve(dbtest.Principal(a.ID, tenant), (&Handler{Service: svc}).Mount)
	codeRe := regexp.MustCompile(`\b\d{6}\b`)

	free := dbtest.Unique("free") + "@example.test"
	freeRec := dbtest.Do(t, as, http.MethodPost, "/me/email/change/start", map[string]any{"email": free})
	if freeRec.Code != http.StatusOK {
		t.Fatalf("start a change to a free address: status %d (%s)", freeRec.Code, freeRec.Body.String())
	}
	freeCode := codeRe.FindString(mail.Last(t).Body)
	if freeCode == "" {
		t.Fatal("no code was sent to the free address")
	}

	for _, held := range []string{holder.Email, strings.ToUpper(holder.Email)} {
		rec := dbtest.Do(t, as, http.MethodPost, "/me/email/change/start", map[string]any{"email": held})
		if rec.Code != freeRec.Code || rec.Body.String() != freeRec.Body.String() {
			t.Errorf("start a change to %s: %d %s, want the free address's %d %s",
				held, rec.Code, rec.Body.String(), freeRec.Code, freeRec.Body.String())
		}
		if msg := mail.Last(t); msg.To != held || codeRe.MatchString(msg.Body) {
			t.Errorf("mail to %s with body %q; want a notice without a code to %s", msg.To, msg.Body, held)
		}
	}

	// The newer request superseded the free address's code, as any newer one does.
	if _, err := svc.ConfirmEmailChange(ctx, a.ID, freeCode, who); !errors.Is(err, errs.ErrVerifyCodeInvalid) {
		t.Errorf("confirm with the superseded code: %v, want %v", err, errs.ErrVerifyCodeInvalid)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND email = $2`, a.ID, a.Email); n != 1 {
		t.Error("the account's address changed")
	}
}
