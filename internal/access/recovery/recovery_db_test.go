//go:build integration

package recovery

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newService returns the recovery service sending through sender, with the
// platform's password rules, magic links on in every organization, no address
// captured and no request bounded.
func newService(t *testing.T, sender notifier.Sender) *Service {
	t.Helper()
	svc, err := NewService(dbtest.Pool(t), Deps{
		Sender: sender, TTL: time.Hour, BaseAppURL: "https://console.example.test", Rules: policies(t),
		MagicLinks: magicLinksOn{}, Capture: noCapture{}, Signals: sessionsignal.New(nil),
		MagicPerAddress: unbounded{}, MagicPerCaller: unbounded{}, ResetPerAddress: unbounded{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// policies returns the authentication policy service, its breach check off.
func policies(t *testing.T) *authpolicy.Service {
	t.Helper()
	svc, err := authpolicy.NewService(dbtest.Pool(t), authpolicy.NoBreachCheck{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// magicLinksOn allows magic links everywhere, with the service's lifetime.
type magicLinksOn struct{}

func (magicLinksOn) MagicLinkPolicy(context.Context, uuid.UUID) (bool, time.Duration, error) {
	return true, 0, nil
}

// noCapture captures no address.
type noCapture struct{}

func (noCapture) RefuseCaptured(context.Context, string) error { return nil }

// unbounded never refuses a request.
type unbounded struct{}

func (unbounded) Take(context.Context, string) (bool, int) { return true, 0 }

// TestPasswordReset checks the reset link end to end: it is mailed only to a
// registered address, sets the new password, ends every session, remembered
// device and application grant, and works once.
func TestPasswordReset(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail := &dbtest.Mailbox{}
	svc := newService(t, mail)
	svc.rules = policies(t)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz-old")
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2), ($1, $2)`, a.ID, organization); err != nil {
		t.Fatalf("sessions: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.trusted_devices (user_id, organization_id, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')
	`, a.ID, organization, dbtest.Unique("device")); err != nil {
		t.Fatalf("trusted device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at)
		VALUES ($1, 'app', $2, $3, NOW() + INTERVAL '1 day')
	`, dbtest.Unique("grant"), a.ID, organization); err != nil {
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
	if err := svc.ConfirmPasswordReset(ctx, token, newPassword, audit.Actor{}); err != nil {
		t.Fatalf("confirm reset: %v", err)
	}
	if m := mail.Last(t); m.To != a.Email || m.Subject != "Your password was reset" || strings.Contains(m.Body, token) {
		t.Errorf("notice %q to %s: %q; want the person told, without the link", m.Subject, m.To, m.Body)
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
	if err := svc.ConfirmPasswordReset(ctx, token, "Pw4!nKx7mQ2v-again", audit.Actor{}); !errors.Is(err, ErrLinkUsed) {
		t.Errorf("second use of the link: %v, want %v", err, ErrLinkUsed)
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
	svc := newService(t, sender)
	h := &Handler{Service: svc}
	srv := chi.NewRouter()
	h.Mount(srv)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	nobody := dbtest.Unique("nobody") + "@example.test"

	for _, path := range []string{"/auth/forgot-password", "/auth/magic-link/start"} {
		answers := map[string]string{}
		for _, email := range []string{a.Email, nobody} {
			rec := dbtest.Do(t, srv, http.MethodPost, path, map[string]any{"email": email, "organization_id": uuid.Nil})
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
// work with only one connection free, while the organization's password rules
// and magic-link policy are read from the database.
func TestRecoveryLinksWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t, &dbtest.Mailbox{})
	policy := policies(t)
	svc.rules = policy
	svc.magicLinks = policy
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	reset, link := dbtest.Unique("reset"), dbtest.Unique("link")
	if _, err := pool.Exec(ctx, `INSERT INTO auth.magic_links (email, token_hash, expires_at, app) VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)`,
		a.Email, codes.Hash(link), MagicLinkConsole); err != nil {
		t.Fatalf("magic link: %v", err)
	}

	// The magic link first: it proves the address, which ends the links still
	// outstanding, so the reset link is issued after it.
	dbtest.LeaveOneConnection(t)
	if res, err := svc.ConsumeMagicLink(ctx, link, audit.Actor{}); err != nil || res.UserID != a.ID {
		t.Errorf("consume magic link: %+v, %v; want %s", res, err, a.ID)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth.password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')`,
		a.ID, codes.Hash(reset)); err != nil {
		t.Fatalf("reset link: %v", err)
	}
	if err := svc.ConfirmPasswordReset(ctx, reset, "Pw4!nKx7mQ2v-new", audit.Actor{}); err != nil {
		t.Errorf("confirm reset: %v", err)
	}
}

// TestRecoveryLinksGoToTheStoredAddress checks that reset and sign-in links
// are sent to the address as the account stores it, whatever case it was
// typed in; that only the newest of each works; that a reset ends the links
// still outstanding; and that resets are bounded per address.
func TestRecoveryLinksGoToTheStoredAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := newService(t, mail)
	policy := policies(t)
	svc.rules = policy
	svc.magicLinks = policy
	organization := dbtest.Organization(t)
	a := dbtest.UserAt(t, "Ada."+dbtest.Unique("Lovelace")+"@example.test", organization, organization)
	tokenOf := func(msg notifier.Message) string {
		t.Helper()
		_, query, _ := strings.Cut(msg.Body, "?")
		link, err := url.ParseQuery(query)
		if msg.To != a.Email || err != nil || link.Get("token") == "" {
			t.Fatalf("mail to %s with body %q; want a link with a token to %s", msg.To, msg.Body, a.Email)
		}
		return link.Get("token")
	}
	reset := func() string {
		t.Helper()
		if _, err := svc.StartPasswordReset(ctx, strings.ToLower(a.Email), ResetOrigin{}); err != nil {
			t.Fatalf("start reset: %v", err)
		}
		svc.deliveries.Wait()
		return tokenOf(mail.Last(t))
	}
	magic := func() string {
		t.Helper()
		if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: strings.ToUpper(a.Email), OrganizationID: organization}); err != nil {
			t.Fatalf("request magic link: %v", err)
		}
		svc.deliveries.Wait()
		return tokenOf(mail.Last(t))
	}

	oldReset, newReset := reset(), reset()
	if err := svc.ConfirmPasswordReset(ctx, oldReset, "Pw4!nKx7mQ2v-old", audit.Actor{}); !errors.Is(err, ErrLinkExpired) {
		t.Errorf("an earlier reset link: %v, want %v", err, ErrLinkExpired)
	}
	oldLink, newLink := magic(), magic()
	if _, err := svc.ConsumeMagicLink(ctx, oldLink, audit.Actor{}); !errors.Is(err, ErrLinkExpired) {
		t.Errorf("an earlier sign-in link: %v, want %v", err, ErrLinkExpired)
	}
	if err := svc.ConfirmPasswordReset(ctx, newReset, "Pw4!nKx7mQ2v-new", audit.Actor{}); err != nil {
		t.Fatalf("the newest reset link: %v", err)
	}
	if _, err := svc.ConsumeMagicLink(ctx, newLink, audit.Actor{}); !errors.Is(err, ErrLinkExpired) {
		t.Errorf("a sign-in link sent before the reset: %v, want %v", err, ErrLinkExpired)
	}

	svc.resetPerAddress = ratelimit.NewWithStore(ratelimit.NewMemStore(), 1.0/300, 1)
	for i, want := range []error{nil, errs.ErrTooManyRequests} {
		if _, err := svc.StartPasswordReset(ctx, strings.ToUpper(a.Email), ResetOrigin{}); !errors.Is(err, want) {
			t.Errorf("reset request %d: %v, want %v", i+1, err, want)
		}
	}
	svc.deliveries.Wait()
}

// credentialKinds counts, per kind, what userID can sign in or act with.
var credentialKinds = map[string]string{
	"password":         `SELECT count(*) FROM auth.password_credentials WHERE user_id = $1`,
	"passkeys":         `SELECT count(*) FROM auth.passkey_credentials WHERE user_id = $1`,
	"authenticator":    `SELECT count(*) FROM auth.mfa_totp WHERE user_id = $1`,
	"recovery codes":   `SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id = $1`,
	"email/SMS codes":  `SELECT count(*) FROM auth.mfa_otp_factors WHERE user_id = $1`,
	"push devices":     `SELECT count(*) FROM auth.mfa_push_devices WHERE user_id = $1`,
	"push pairings":    `SELECT count(*) FROM auth.mfa_push_pairings WHERE user_id = $1 AND used_at IS NULL`,
	"linked accounts":  `SELECT count(*) FROM account.external_identities WHERE user_id = $1`,
	"console sign-ins": `SELECT count(*) FROM auth.platform_social_identities WHERE user_id = $1`,
	"API keys":         `SELECT count(*) FROM auth.api_keys WHERE user_id = $1 AND revoked_at IS NULL`,
}

// giveCredentials gives a one of each credential kind, as someone who
// registered the address could have set up, in organization.
func giveCredentials(t *testing.T, a dbtest.Account, organization uuid.UUID) {
	t.Helper()
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz-squat")
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, name) VALUES ($1, convert_to($2, 'UTF8'), '\x00', 'Laptop')`, []any{a.ID, a.ID.String()}},
		{`INSERT INTO auth.mfa_totp (user_id, secret_ct, secret_nonce, confirmed_at) VALUES ($1, '\x00', '\x00', NOW())`, []any{a.ID}},
		{`INSERT INTO auth.mfa_recovery_codes (user_id, code_hash) VALUES ($1, 'hash')`, []any{a.ID}},
		{`INSERT INTO auth.mfa_otp_factors (user_id, channel, destination) VALUES ($1, 'sms', '+15550100')`, []any{a.ID}},
		{`INSERT INTO auth.mfa_push_devices (user_id, platform, push_token_ct, push_token_nonce, push_token_hash, device_token_hash) VALUES ($1, 'ios', '\x00', '\x00', 'push', 'device')`, []any{a.ID}},
		{`INSERT INTO auth.mfa_push_pairings (user_id, code_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')`, []any{a.ID, dbtest.Unique("pair")}},
		{`INSERT INTO account.external_identities (user_id, organization_id, provider, subject, email) VALUES ($1, $2, 'github', $3, $4)`, []any{a.ID, organization, dbtest.Unique("gh"), a.Email}},
		{`INSERT INTO auth.platform_social_identities (user_id, provider, subject, email) VALUES ($1, 'google', $2, $3)`, []any{a.ID, dbtest.Unique("g"), a.Email}},
		{`INSERT INTO auth.api_keys (organization_id, user_id, name, prefix, key_hash) VALUES ($1, $2, 'laptop', $3, 'hash')`, []any{organization, a.ID, dbtest.Unique("qk")}},
	} {
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
}

// heldCredentials returns the credential kinds a holds, with how many of each.
func heldCredentials(t *testing.T, a dbtest.Account) map[string]int {
	t.Helper()
	held := map[string]int{}
	for kind, q := range credentialKinds {
		if n := dbtest.Count(t, q, a.ID); n > 0 {
			held[kind] = n
		}
	}
	return held
}

// TestResetThatProvesTheAddressEndsEarlierCredentials checks that a reset that
// proves an account's address for the first time leaves it only the password
// just set: whatever someone who registered the address first set up is gone,
// and the removal is recorded.
func TestResetThatProvesTheAddressEndsEarlierCredentials(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t, &dbtest.Mailbox{})
	svc.rules = policies(t)
	organization := dbtest.Organization(t)
	squatted := dbtest.User(t, organization, organization)
	giveCredentials(t, squatted, organization)

	raw, err := svc.StartPasswordReset(ctx, squatted.Email, ResetOrigin{})
	svc.deliveries.Wait()
	if err != nil || raw == "" {
		t.Fatalf("start a reset: %q, %v", raw, err)
	}
	if err := svc.ConfirmPasswordReset(ctx, raw, "Pw4!nKx7mQ2v-owner", audit.Actor{}); err != nil {
		t.Fatalf("confirm the reset: %v", err)
	}
	if held := heldCredentials(t, squatted); len(held) != 1 || held["password"] != 1 {
		t.Errorf("after the reset that proved the address the account holds %v; want only the new password", held)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.credentials_removed' AND resource_id = $1
		AND organization_id = $2 AND metadata->>'proof' = 'password_reset'`, squatted.ID, organization); n != 1 {
		t.Errorf("the removal was recorded %d times, want once", n)
	}
}

// TestResetOfAVerifiedAccountKeepsItsPasskeys checks that a reset of an account
// whose address was already proved changes only its password.
func TestResetOfAVerifiedAccountKeepsItsPasskeys(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t, &dbtest.Mailbox{})
	svc.rules = policies(t)
	organization := dbtest.Organization(t)
	owner := dbtest.User(t, organization, organization)
	giveCredentials(t, owner, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	before := heldCredentials(t, owner)

	raw, err := svc.StartPasswordReset(ctx, owner.Email, ResetOrigin{})
	svc.deliveries.Wait()
	if err != nil || raw == "" {
		t.Fatalf("start a reset: %q, %v", raw, err)
	}
	if err := svc.ConfirmPasswordReset(ctx, raw, "Pw4!nKx7mQ2v-owner", audit.Actor{}); err != nil {
		t.Fatalf("confirm the reset: %v", err)
	}
	if after := heldCredentials(t, owner); !maps.Equal(after, before) {
		t.Errorf("a verified account's reset left %v, want %v", after, before)
	}
}

// captureDomain refuses every address on its domain, as an organization that
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
	svc := newService(t, mail)
	policy := policies(t)
	svc.rules = policy
	svc.magicLinks = policy
	organization := dbtest.Organization(t)
	domain := dbtest.Unique("acme") + ".example.test"
	a := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz-old")
	reset, link := dbtest.Unique("reset"), dbtest.Unique("link")
	if _, err := pool.Exec(ctx, `
		WITH r AS (INSERT INTO auth.password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour'))
		INSERT INTO auth.magic_links (email, token_hash, expires_at, app) VALUES ($3, $4, NOW() + INTERVAL '1 hour', $5)
	`, a.ID, codes.Hash(reset), a.Email, codes.Hash(link), MagicLinkConsole); err != nil {
		t.Fatalf("links: %v", err)
	}
	svc.capture = captureDomain(domain)

	for _, email := range []string{a.Email, dbtest.Unique("nobody") + "@" + domain} {
		if _, err := svc.StartPasswordReset(ctx, email, ResetOrigin{}); !errors.Is(err, errs.ErrAuthSSORequired) {
			t.Errorf("reset for %s: %v, want %v", email, err, errs.ErrAuthSSORequired)
		}
		if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: email, OrganizationID: organization}); !errors.Is(err, errs.ErrAuthSSORequired) {
			t.Errorf("magic link for %s: %v, want %v", email, err, errs.ErrAuthSSORequired)
		}
	}
	if _, err := svc.ConsumeMagicLink(ctx, link, audit.Actor{}); !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Errorf("a magic link issued before the capture: %v, want %v", err, errs.ErrAuthSSORequired)
	}
	if err := svc.ConfirmPasswordReset(ctx, reset, "Pw4!nKx7mQ2v-new", audit.Actor{}); !errors.Is(err, errs.ErrAuthSSORequired) {
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

	other := dbtest.User(t, organization, organization)
	if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: other.Email, OrganizationID: organization}); err != nil {
		t.Fatalf("magic link for an address on no captured domain: %v", err)
	}
	svc.deliveries.Wait()
	if msg := mail.Last(t); msg.To != other.Email {
		t.Errorf("magic link sent to %s, want %s", msg.To, other.Email)
	}
}

// recorded is one audit row of a recovery flow, as the trail keeps it.
type recorded struct {
	actorType, ip, userAgent, requestID string
	actorUserID                         *uuid.UUID
}

// recordedAs reads the one row of action about userID in organization's trail.
func recordedAs(t *testing.T, action string, organization, userID uuid.UUID) recorded {
	t.Helper()
	var r recorded
	if err := dbtest.Pool(t).QueryRow(context.Background(), `
		SELECT actor_type, actor_user_id, COALESCE(host(ip), ''), COALESCE(user_agent, ''), COALESCE(request_id, '')
		FROM audit.events WHERE action = $1 AND organization_id = $2 AND resource_id = $3`,
		action, organization, userID).Scan(&r.actorType, &r.actorUserID, &r.ip, &r.userAgent, &r.requestID); err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

// TestRecoveryRecordsTheRequest checks that the password-reset and magic-link
// rows carry the request's client address, user agent and request ID, with the
// actor each flow names whoever the request's principal was: anonymous for a
// request, the account for the proof of its address, the system for the reset
// and the sign-in.
func TestRecoveryRecordsTheRequest(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	svc := newService(t, mail)
	svc.rules = policies(t)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	someone := uuid.New()
	from := func(rid string) audit.Actor {
		return audit.Actor{UserID: &someone, Type: "user", IP: "203.0.113.9", UserAgent: "recovery-test", RequestID: rid}
	}
	check := func(action string, wantType string, wantUser *uuid.UUID, rid string) {
		t.Helper()
		got := recordedAs(t, action, organization, a.ID)
		if got.actorType != wantType || (got.actorUserID == nil) != (wantUser == nil) ||
			(wantUser != nil && *got.actorUserID != *wantUser) ||
			got.ip != "203.0.113.9" || got.userAgent != "recovery-test" || got.requestID != rid {
			t.Errorf("%s recorded %+v (user %v); want actor %s %v from 203.0.113.9, recovery-test, %s",
				action, got, got.actorUserID, wantType, wantUser, rid)
		}
	}

	if _, err := svc.StartPasswordReset(ctx, a.Email, ResetOrigin{Actor: from("reset-asked")}); err != nil {
		t.Fatal(err)
	}
	svc.deliveries.Wait()
	check("auth.password_reset_requested", "anonymous", nil, "reset-asked")
	if err := svc.ConfirmPasswordReset(ctx, tokenIn(t, mail.Last(t)), "Pw4!nKx7mQ2v-new", from("reset-used")); err != nil {
		t.Fatal(err)
	}
	check("email.verified", "user", &a.ID, "reset-used")
	check("auth.password_reset_confirmed", "system", &a.ID, "reset-used")

	if err := svc.RequestMagicLink(ctx, MagicLinkRequest{Email: a.Email, Actor: from("link-asked")}); err != nil {
		t.Fatal(err)
	}
	svc.deliveries.Wait()
	check("auth.magic_link_requested", "anonymous", nil, "link-asked")
	if _, err := svc.ConsumeMagicLink(ctx, tokenIn(t, mail.Last(t)), from("link-used")); err != nil {
		t.Fatal(err)
	}
	check("auth.magic_link_consumed", "system", &a.ID, "link-used")
}
