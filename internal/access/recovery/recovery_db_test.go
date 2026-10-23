//go:build integration

package recovery

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestPasswordReset checks the reset link end to end: it is mailed only to a
// registered address, sets the new password, ends every session, remembered
// device and application grant, and works once.
func TestPasswordReset(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail := &dbtest.Mailbox{}
	svc := NewService(pool, mail, time.Hour, "https://console.example.test")
	svc.SetPasswordRules(authpolicy.NewService(pool))
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz-old")
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2), ($1, $2)`, a.ID, tenant); err != nil {
		t.Fatalf("sessions: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')
	`, a.ID, tenant, dbtest.Unique("device")); err != nil {
		t.Fatalf("trusted device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, expires_at)
		VALUES ($1, 'app', $2, $3, NOW() + INTERVAL '1 day')
	`, dbtest.Unique("grant"), a.ID, tenant); err != nil {
		t.Fatalf("application grant: %v", err)
	}

	raw, err := svc.StartPasswordReset(ctx, dbtest.Unique("nobody")+"@example.test", ResetOrigin{})
	svc.deliveries.Wait()
	if err != nil || raw != "" || mail.Len() != 0 {
		t.Fatalf("reset for an unknown address: token %q, %v, %d mails; want none", raw, err, mail.Len())
	}
	if _, err := svc.StartPasswordReset(ctx, a.Email, ResetOrigin{}); err != nil {
		t.Fatalf("start reset: %v", err)
	}
	svc.deliveries.Wait()
	msg := mail.Last(t)
	_, query, _ := strings.Cut(msg.Body, "?")
	link, err := url.ParseQuery(query)
	if msg.To != a.Email || err != nil || link.Get("token") == "" {
		t.Fatalf("reset mail to %s with body %q; want a link with a token to %s", msg.To, msg.Body, a.Email)
	}
	token := link.Get("token")

	const newPassword = "Pw4!nKx7mQ2v-new"
	if err := svc.ConfirmPasswordReset(ctx, token, newPassword, AuditCtx{}); err != nil {
		t.Fatalf("confirm reset: %v", err)
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id = $1`, a.ID).Scan(&hash); err != nil {
		t.Fatalf("read password: %v", err)
	}
	if !password.Verify(hash, newPassword) || password.Verify(hash, "Kx7mQ2vLp9Wz-old") {
		t.Error("the reset did not replace the password")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`, a.ID); n != 0 {
		t.Errorf("%d sessions survived the reset", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d remembered devices survived the reset", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, a.ID); n != 0 {
		t.Errorf("%d application grants survived the reset", n)
	}
	if err := svc.ConfirmPasswordReset(ctx, token, "Pw4!nKx7mQ2v-again", AuditCtx{}); !errors.Is(err, errs.ErrRecoveryLinkUsed) {
		t.Errorf("second use of the link: %v, want %v", err, errs.ErrRecoveryLinkUsed)
	}
}

// refusingSender refuses every message, as the delivery tracker does for a
// suppressed address.
type refusingSender struct{ sent chan notifier.Message }

func (r refusingSender) Send(_ context.Context, m notifier.Message) error {
	r.sent <- m
	return errs.ErrEmailSuppressed
}

// TestRecoveryRequestsAnswerAlike checks that a forgot-password or magic-link
// request gets the same answer for a registered address whose mail is refused
// as for an address with no account.
func TestRecoveryRequestsAnswerAlike(t *testing.T) {
	sender := refusingSender{sent: make(chan notifier.Message, 4)}
	svc := NewService(dbtest.Pool(t), sender, time.Hour, "https://console.example.test")
	h := &Handler{Service: svc}
	srv := chi.NewRouter()
	h.Mount(srv)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	nobody := dbtest.Unique("nobody") + "@example.test"

	for _, path := range []string{"/auth/forgot-password", "/auth/magic-link/start"} {
		answers := map[string]string{}
		for _, email := range []string{a.Email, nobody} {
			rec := dbtest.Do(t, srv, http.MethodPost, path, map[string]any{"email": email, "tenant_id": uuid.Nil})
			answers[email] = rec.Body.String()
			if rec.Code != http.StatusOK {
				t.Errorf("%s for %s: %d %s, want 200", path, email, rec.Code, rec.Body.String())
			}
		}
		if answers[a.Email] != answers[nobody] {
			t.Errorf("%s answers %q for an account and %q for none", path, answers[a.Email], answers[nobody])
		}
		svc.deliveries.Wait()
		select {
		case m := <-sender.sent:
			if m.To != a.Email {
				t.Errorf("%s mailed %s, want %s", path, m.To, a.Email)
			}
		default:
			t.Errorf("%s sent nothing to the registered address", path)
		}
	}
}

// TestRecoveryLinksWithOneConnection checks that a reset link and a magic link
// work with only one connection free, while the organisation's password rules
// and magic-link policy are read from the database.
func TestRecoveryLinksWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, &dbtest.Mailbox{}, time.Hour, "https://console.example.test")
	policy := authpolicy.NewService(pool)
	svc.SetPasswordRules(policy)
	svc.SetMagicLinkPolicy(policy)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	reset, link := dbtest.Unique("reset"), dbtest.Unique("link")
	if _, err := pool.Exec(ctx, `
		WITH r AS (INSERT INTO auth.password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour'))
		INSERT INTO auth.magic_links (email, token_hash, expires_at, app) VALUES ($3, $4, NOW() + INTERVAL '1 hour', $5)
	`, a.ID, codes.Hash(reset), a.Email, codes.Hash(link), MagicLinkConsole); err != nil {
		t.Fatalf("links: %v", err)
	}

	dbtest.LeaveOneConnection(t)
	if err := svc.ConfirmPasswordReset(ctx, reset, "Pw4!nKx7mQ2v-new", AuditCtx{}); err != nil {
		t.Errorf("confirm reset: %v", err)
	}
	if res, err := svc.ConsumeMagicLink(ctx, link, AuditCtx{}); err != nil || res.UserID != a.ID {
		t.Errorf("consume magic link: %+v, %v; want %s", res, err, a.ID)
	}
}
