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
	codeRe := regexp.MustCompile(`\b\d{8}\b`)

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

// TestEmailChangeEndsLinksToTheOldAddress checks that a confirmed change of
// address ends the reset and sign-in links already sent to the old one.
func TestEmailChangeEndsLinksToTheOldAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(pool, mail, 10*time.Minute)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}, TenantID: &tenant}
	if _, err := pool.Exec(ctx, `
		WITH r AS (INSERT INTO auth.password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour'))
		INSERT INTO auth.magic_links (email, token_hash, expires_at, app) VALUES ($3, $4, NOW() + INTERVAL '1 hour', 'console')
	`, a.ID, dbtest.Unique("reset"), strings.ToUpper(a.Email), dbtest.Unique("link")); err != nil {
		t.Fatal(err)
	}
	as := dbtest.Serve(dbtest.Principal(a.ID, tenant), (&Handler{Service: svc}).Mount)
	if rec := dbtest.Do(t, as, http.MethodPost, "/me/email/change/start", map[string]any{"email": dbtest.Unique("moved") + "@example.test"}); rec.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	code := regexp.MustCompile(`\b\d{8}\b`).FindString(mail.Last(t).Body)
	if _, err := svc.ConfirmEmailChange(ctx, a.ID, code, who); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if n := dbtest.Count(t, `
		SELECT (SELECT count(*) FROM auth.password_resets WHERE user_id = $1 AND expires_at > NOW())
		     + (SELECT count(*) FROM auth.magic_links WHERE LOWER(email) = LOWER($2) AND expires_at > NOW())
	`, a.ID, a.Email); n != 0 {
		t.Errorf("%d links to the old address still work", n)
	}
}

// TestCapturedMemberCannotMoveOffTheManagedDomain checks that an address on a
// domain the account's organisation manages moves only to another of its
// domains, that an address the directory or single sign-on provides doesn't
// move, and that no address moves onto a domain another organisation manages,
// when the change starts and when it is confirmed; and that other moves work.
func TestCapturedMemberCannotMoveOffTheManagedDomain(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(pool, mail, 10*time.Minute)
	tenant := dbtest.Tenant(t)
	domain := dbtest.Domain(t, tenant)
	elsewhere := dbtest.Domain(t, dbtest.Tenant(t))
	start := func(a dbtest.Account, email string) (int, string) {
		t.Helper()
		as := dbtest.Serve(dbtest.Principal(a.ID, tenant), (&Handler{Service: svc}).Mount)
		rec := dbtest.Do(t, as, http.MethodPost, "/me/email/change/start", map[string]any{"email": email})
		return rec.Code, rec.Body.String()
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	free := func() string { return dbtest.Unique("free") + "@example.test" }

	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, tenant, tenant)
	directory := dbtest.User(t, tenant, tenant)
	exec(`UPDATE "user".users SET provisioned_via = 'scim' WHERE id = $1`, directory.ID)
	sso := dbtest.User(t, tenant, tenant)
	var conn string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.saml_connections (tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
		VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', 'active') RETURNING id`, tenant).Scan(&conn); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO "user".external_identities (user_id, tenant_id, provider, connection_id, subject) VALUES ($1, $2, 'saml', $3, 'okta|sso')`, sso.ID, tenant, conn)
	plain := dbtest.User(t, tenant, tenant)
	for name, c := range map[string]struct {
		a     dbtest.Account
		email string
	}{
		"off the organisation's domain":              {member, free()},
		"an address the directory provides":          {directory, free()},
		"an address single sign-on provides":         {sso, free()},
		"onto a domain another organisation manages": {plain, dbtest.Unique("x") + "@" + elsewhere},
	} {
		if status, body := start(c.a, c.email); status != http.StatusForbidden || !strings.Contains(body, errs.CodeVerifyEmailManaged) {
			t.Errorf("a change %s: %d %s, want 403 %s", name, status, body, errs.CodeVerifyEmailManaged)
		}
	}
	for name, c := range map[string]struct {
		a     dbtest.Account
		email string
	}{
		"within the organisation's domain": {member, dbtest.Unique("asha.k") + "@" + domain},
		"between free addresses":           {plain, free()},
	} {
		if status, body := start(c.a, c.email); status != http.StatusOK {
			t.Errorf("a change %s: %d %s, want 200", name, status, body)
		}
	}

	// The organisation verifies the domain between start and confirm.
	late := dbtest.Unique("late") + ".example.test"
	moving := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+late, tenant, tenant)
	if status, body := start(moving, free()); status != http.StatusOK {
		t.Fatalf("start before the domain is verified: %d %s", status, body)
	}
	code := regexp.MustCompile(`\b\d{8}\b`).FindString(mail.Last(t).Body)
	exec(`INSERT INTO tenant.domains (tenant_id, domain, verification_token, verified_at) VALUES ($1, $2, 'test', NOW())`, tenant, late)
	who := Requester{Actor: audit.Actor{UserID: &moving.ID, Type: "user"}, TenantID: &tenant}
	if _, err := svc.ConfirmEmailChange(ctx, moving.ID, code, who); !errors.Is(err, errs.ErrVerifyEmailManaged) {
		t.Errorf("confirm a move off a domain verified since the start: %v, want %v", err, errs.ErrVerifyEmailManaged)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND email = $2`, moving.ID, moving.Email); n != 1 {
		t.Error("the address moved off a domain its organisation manages")
	}
}
