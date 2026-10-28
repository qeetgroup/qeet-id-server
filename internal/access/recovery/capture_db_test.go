//go:build integration

package recovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// captureDomain refuses every address on its domain, as an organisation that
// requires single sign-on there does.
type captureDomain string

func (d captureDomain) RefuseCaptured(_ context.Context, email string) error {
	if strings.HasSuffix(strings.ToLower(email), "@"+string(d)) {
		return errs.ErrAuthSSORequired
	}
	return nil
}

// TestCapturedAddressesGetNoLinks checks that an address on a captured domain
// is refused a reset link and a magic link with auth.sso_required, with or
// without an account and with nothing sent; that links issued before the
// capture stop working and stay unused; and that other addresses get theirs.
func TestCapturedAddressesGetNoLinks(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(pool, mail, time.Hour, "https://console.example.test")
	policy := authpolicy.NewService(pool)
	svc.SetPasswordRules(policy)
	svc.SetMagicLinkPolicy(policy)
	tenant := dbtest.Tenant(t)
	domain := dbtest.Unique("acme") + ".example.test"
	a := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, tenant, tenant)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz-old")
	reset, link := dbtest.Unique("reset"), dbtest.Unique("link")
	if _, err := pool.Exec(ctx, `
		WITH r AS (INSERT INTO auth.password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour'))
		INSERT INTO auth.magic_links (email, token_hash, expires_at, app) VALUES ($3, $4, NOW() + INTERVAL '1 hour', $5)
	`, a.ID, codes.Hash(reset), a.Email, codes.Hash(link), MagicLinkConsole); err != nil {
		t.Fatalf("links: %v", err)
	}
	svc.SetDomainCapture(captureDomain(domain))

	for _, email := range []string{a.Email, dbtest.Unique("nobody") + "@" + domain} {
		if _, err := svc.StartPasswordReset(ctx, email, ResetOrigin{}); !errors.Is(err, errs.ErrAuthSSORequired) {
			t.Errorf("reset for %s: %v, want %v", email, err, errs.ErrAuthSSORequired)
		}
		if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: email, TenantID: tenant}); !errors.Is(err, errs.ErrAuthSSORequired) {
			t.Errorf("magic link for %s: %v, want %v", email, err, errs.ErrAuthSSORequired)
		}
	}
	if _, err := svc.ConsumeMagicLink(ctx, link, AuditCtx{}); !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Errorf("a magic link issued before the capture: %v, want %v", err, errs.ErrAuthSSORequired)
	}
	if err := svc.ConfirmPasswordReset(ctx, reset, "Pw4!nKx7mQ2v-new", AuditCtx{}); !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Errorf("a reset link issued before the capture: %v, want %v", err, errs.ErrAuthSSORequired)
	}
	svc.deliveries.Wait()
	if mail.Len() != 0 {
		t.Errorf("%d messages sent to a captured domain, want none", mail.Len())
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id = $1`, a.ID).Scan(&hash); err != nil || !password.Verify(hash, "Kx7mQ2vLp9Wz-old") {
		t.Errorf("the password changed on a captured domain (%v)", err)
	}
	if n := dbtest.Count(t, `
		SELECT (SELECT count(*) FROM auth.password_resets WHERE token_hash = $1 AND used_at IS NULL)
		     + (SELECT count(*) FROM auth.magic_links WHERE token_hash = $2 AND used_at IS NULL)
	`, codes.Hash(reset), codes.Hash(link)); n != 2 {
		t.Errorf("%d of the two refused links stay unused, want both", n)
	}

	other := dbtest.User(t, tenant, tenant)
	if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: other.Email, TenantID: tenant}); err != nil {
		t.Fatalf("magic link for an address on no captured domain: %v", err)
	}
	svc.deliveries.Wait()
	if msg := mail.Last(t); msg.To != other.Email {
		t.Errorf("magic link sent to %s, want %s", msg.To, other.Email)
	}
}
