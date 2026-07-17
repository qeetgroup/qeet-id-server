//go:build integration

package integration

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/domains/access/recovery"
	"github.com/qeetgroup/qeet-id/platform/messaging/notifier"
	password "github.com/qeetgroup/qeet-id/platform/security/encryption"
)

// captureSender records the emails the recovery service "sends" so tests can
// pull the one-time token out of the body — and assert that enumeration-safe
// flows never send at all.
type captureSender struct {
	mu   sync.Mutex
	msgs []notifier.Message
}

func (c *captureSender) Send(_ context.Context, m notifier.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

func (c *captureSender) last() (notifier.Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.msgs) == 0 {
		return notifier.Message{}, false
	}
	return c.msgs[len(c.msgs)-1], true
}

func (c *captureSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

// tokenFromBody extracts the `token=` value from a recovery email body — both
// the reset and magic-link links end in `...?token=<raw>`.
func tokenFromBody(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token= in email body: %q", body)
	}
	return strings.TrimSpace(body[i+len("token="):])
}

func createTenantUser(t *testing.T, ctx context.Context, tenantID uuid.UUID, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id`,
		tenantID, email).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

func newRecovery(sender notifier.Sender) *recovery.Service {
	return recovery.NewService(testPool, sender, time.Hour, "http://app.test", "http://login.test")
}

// Full password-reset round-trip: a reset email is emitted, the emailed token
// sets a new password (verifiable against the stored hash), and the token is
// single-use.
func TestPasswordReset_RoundTripAndSingleUse(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("recov"))
	email := uniqueSlug("reset") + "@example.com"
	userID := createTenantUser(t, ctx, tid, email)

	sender := &captureSender{}
	svc := newRecovery(sender)

	if err := svc.StartPasswordReset(ctx, tid, email); err != nil {
		t.Fatalf("StartPasswordReset: %v", err)
	}
	msg, ok := sender.last()
	if !ok || msg.To != email {
		t.Fatalf("expected reset email to %s, got %+v (ok=%v)", email, msg, ok)
	}
	token := tokenFromBody(t, msg.Body)

	const newPass = "Kx7mQ2vLp9Wz"
	if err := svc.ConfirmPasswordReset(ctx, token, newPass, recovery.AuditCtx{}); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}

	// The new password must verify against the stored credential hash.
	var hash string
	if err := testPool.QueryRow(ctx,
		`SELECT password_hash FROM auth.password_credentials WHERE user_id = $1`, userID).Scan(&hash); err != nil {
		t.Fatalf("read credential: %v", err)
	}
	if !password.Verify(hash, newPass) {
		t.Fatal("new password does not verify against the stored hash")
	}

	// Single-use: replaying the same token must be rejected.
	if err := svc.ConfirmPasswordReset(ctx, token, newPass, recovery.AuditCtx{}); err == nil {
		t.Fatal("reusing an already-consumed reset token should fail")
	}
}

// Weak passwords are rejected before any token lookup, and an unknown token is
// rejected for a strong password.
func TestPasswordReset_RejectsWeakAndInvalid(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newRecovery(&captureSender{})

	if err := svc.ConfirmPasswordReset(ctx, "any-token", "short", recovery.AuditCtx{}); err == nil {
		t.Fatal("a too-short password should be rejected")
	}
	if err := svc.ConfirmPasswordReset(ctx, "no-such-token", "Kx7mQ2vLp9Wz", recovery.AuditCtx{}); err == nil {
		t.Fatal("an unknown reset token should be rejected")
	}
}

// An expired reset token is rejected even though it was valid when issued.
func TestPasswordReset_ExpiredToken(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("recov"))
	email := uniqueSlug("exp") + "@example.com"
	userID := createTenantUser(t, ctx, tid, email)

	sender := &captureSender{}
	svc := newRecovery(sender)
	if err := svc.StartPasswordReset(ctx, tid, email); err != nil {
		t.Fatalf("StartPasswordReset: %v", err)
	}
	msg, _ := sender.last()
	token := tokenFromBody(t, msg.Body)

	// Force the reset row to be in the past.
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.password_resets SET expires_at = NOW() - interval '1 hour' WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("expire token: %v", err)
	}
	if err := svc.ConfirmPasswordReset(ctx, token, "Kx7mQ2vLp9Wz", recovery.AuditCtx{}); err == nil {
		t.Fatal("an expired reset token should be rejected")
	}
}

// Requesting a reset for an unknown email is a silent no-op — no error and no
// email — so an attacker can't probe which addresses have accounts.
func TestPasswordReset_EnumerationSafe(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("recov"))
	sender := &captureSender{}
	svc := newRecovery(sender)

	unknown := uniqueSlug("ghost") + "@example.com"
	if err := svc.StartPasswordReset(ctx, tid, unknown); err != nil {
		t.Fatalf("StartPasswordReset for unknown user should be a silent no-op, got: %v", err)
	}
	if n := sender.count(); n != 0 {
		t.Fatalf("no email should be sent for an unknown user; got %d", n)
	}
}

// Magic-link round-trip: the emailed token resolves to the right user/tenant and
// is single-use.
func TestMagicLink_RoundTripAndSingleUse(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("recov"))
	email := uniqueSlug("magic") + "@example.com"
	userID := createTenantUser(t, ctx, tid, email)

	sender := &captureSender{}
	svc := newRecovery(sender)
	if err := svc.StartMagicLink(ctx, tid, email); err != nil {
		t.Fatalf("StartMagicLink: %v", err)
	}
	msg, ok := sender.last()
	if !ok || msg.To != email {
		t.Fatalf("expected magic-link email to %s, got %+v (ok=%v)", email, msg, ok)
	}
	token := tokenFromBody(t, msg.Body)

	res, err := svc.ConsumeMagicLink(ctx, token, recovery.AuditCtx{})
	if err != nil {
		t.Fatalf("ConsumeMagicLink: %v", err)
	}
	if res.UserID != userID || res.TenantID != tid {
		t.Fatalf("result mismatch: got %+v, want user %s tenant %s", res, userID, tid)
	}
	if _, err := svc.ConsumeMagicLink(ctx, token, recovery.AuditCtx{}); err == nil {
		t.Fatal("a magic-link token should be single-use")
	}
}
