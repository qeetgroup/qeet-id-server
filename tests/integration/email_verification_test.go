//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/verification"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// mailbox keeps every message sent, so a test can read a code from the right
// inbox and see notices.
type mailbox struct {
	mu   sync.Mutex
	sent []notifier.Message
}

func (m *mailbox) Send(_ context.Context, msg notifier.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

// codeFor returns the code in the newest message sent to addr.
func (m *mailbox) codeFor(t *testing.T, addr string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == addr {
			if c := sixDigits.FindString(m.sent[i].Body); c != "" {
				return c
			}
		}
	}
	t.Fatalf("no code was sent to %s", addr)
	return ""
}

func (m *mailbox) count(addr string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, msg := range m.sent {
		if msg.To == addr {
			n++
		}
	}
	return n
}

// TestEmailCodesProveOnlyTheirOwnAddress pins the email-verification codes to
// the flow and address they were issued for: a code sent to a new address for
// an address change can't verify the address on file, a verification code
// can't complete an address change, and each step leaves an audit row.
func TestEmailCodesProveOnlyTheirOwnAddress(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	inbox := &mailbox{}
	svc := verification.NewService(testPool, inbox, 10*time.Minute)

	newUser := func(t *testing.T) (uuid.UUID, string, verification.Requester) {
		t.Helper()
		email := uniqueSlug("owner") + "@corp.example"
		var id uuid.UUID
		if err := testPool.QueryRow(ctx,
			`INSERT INTO "user".users (email) VALUES ($1) RETURNING id`, email).Scan(&id); err != nil {
			t.Fatalf("create user: %v", err)
		}
		uid := id
		return id, email, verification.Requester{Actor: audit.Actor{Type: "user", UserID: &uid}}
	}
	verified := func(t *testing.T, id uuid.UUID) bool {
		t.Helper()
		var at *time.Time
		if err := testPool.QueryRow(ctx, `SELECT email_verified_at FROM "user".users WHERE id = $1`, id).Scan(&at); err != nil {
			t.Fatalf("read user: %v", err)
		}
		return at != nil
	}
	emailOf := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		var e string
		if err := testPool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, id).Scan(&e); err != nil {
			t.Fatalf("read user: %v", err)
		}
		return e
	}
	audits := func(t *testing.T, id uuid.UUID, action string) []map[string]any {
		t.Helper()
		rows, err := testPool.Query(ctx,
			`SELECT metadata FROM audit.events WHERE resource_id = $1 AND action = $2 ORDER BY created_at`, id, action)
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var md map[string]any
			if err := rows.Scan(&md); err != nil {
				t.Fatalf("scan audit: %v", err)
			}
			out = append(out, md)
		}
		return out
	}

	t.Run("an address-change code can't verify the address on file", func(t *testing.T) {
		id, _, who := newUser(t)
		own := uniqueSlug("attacker") + "@own.example"
		if err := svc.StartEmailChange(ctx, id, own, who); err != nil {
			t.Fatalf("start change: %v", err)
		}
		err := svc.ConfirmEmail(ctx, id, inbox.codeFor(t, own), who)
		if !errors.Is(err, errs.ErrVerifyCodeInvalid) {
			t.Fatalf("err = %v, want %v", err, errs.ErrVerifyCodeInvalid)
		}
		if verified(t, id) {
			t.Fatal("a code sent to another inbox verified the address on file")
		}
		if len(audits(t, id, "email.verification_failed")) == 0 {
			t.Fatal("the refused verification was not audited")
		}
	})

	t.Run("a verification code can't complete an address change", func(t *testing.T) {
		id, email, who := newUser(t)
		if err := svc.StartEmail(ctx, id, "", who); err != nil {
			t.Fatalf("start verify: %v", err)
		}
		if _, err := svc.ConfirmEmailChange(ctx, id, inbox.codeFor(t, email), who); !errors.Is(err, errs.ErrVerifyCodeInvalid) {
			t.Fatalf("err = %v, want %v", err, errs.ErrVerifyCodeInvalid)
		}
		if got := emailOf(t, id); got != email {
			t.Fatalf("email = %s, want %s", got, email)
		}
	})

	t.Run("a verification code for the address on file verifies it", func(t *testing.T) {
		id, email, who := newUser(t)
		if err := svc.StartEmail(ctx, id, "", who); err != nil {
			t.Fatalf("start verify: %v", err)
		}
		if err := svc.ConfirmEmail(ctx, id, inbox.codeFor(t, email), who); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		if !verified(t, id) {
			t.Fatal("the address was not verified")
		}
		if len(audits(t, id, "email.verification_started")) != 1 || len(audits(t, id, "email.verified")) != 1 {
			t.Fatal("verification_started / verified audit rows missing")
		}
	})

	t.Run("an address change moves the account, audits both addresses and tells the old inbox", func(t *testing.T) {
		id, old, who := newUser(t)
		next := uniqueSlug("moved") + "@corp.example"
		before := inbox.count(old)
		if err := svc.StartEmailChange(ctx, id, next, who); err != nil {
			t.Fatalf("start change: %v", err)
		}
		got, err := svc.ConfirmEmailChange(ctx, id, inbox.codeFor(t, next), who)
		if err != nil {
			t.Fatalf("confirm change: %v", err)
		}
		if got != next || emailOf(t, id) != next || !verified(t, id) {
			t.Fatalf("after the change: returned %s, stored %s, verified %v", got, emailOf(t, id), verified(t, id))
		}
		changes := audits(t, id, "email.changed")
		if len(changes) != 1 || changes[0]["old_email"] != old || changes[0]["new_email"] != next {
			t.Fatalf("email.changed audit = %v, want old %s and new %s", changes, old, next)
		}
		if inbox.count(old) != before+1 {
			t.Fatal("the previous address was not told about the change")
		}
	})

	t.Run("sending a verification code retires an open address-change code", func(t *testing.T) {
		id, _, who := newUser(t)
		next := uniqueSlug("pending") + "@corp.example"
		if err := svc.StartEmailChange(ctx, id, next, who); err != nil {
			t.Fatalf("start change: %v", err)
		}
		change := inbox.codeFor(t, next)
		if err := svc.StartEmail(ctx, id, "", who); err != nil {
			t.Fatalf("start verify: %v", err)
		}
		if _, err := svc.ConfirmEmailChange(ctx, id, change, who); err == nil {
			t.Fatal("an address-change code still worked after a verification code was sent")
		}
	})

	t.Run("a wrong code is audited as a failed verification", func(t *testing.T) {
		id, _, who := newUser(t)
		if err := svc.StartEmail(ctx, id, "", who); err != nil {
			t.Fatalf("start verify: %v", err)
		}
		if err := svc.ConfirmEmail(ctx, id, "000000", who); err == nil {
			t.Fatal("a wrong code was accepted")
		}
		failed := audits(t, id, "email.verification_failed")
		if len(failed) != 1 || failed[0]["purpose"] != "verify_email" {
			t.Fatalf("email.verification_failed audit = %v", failed)
		}
	})

	t.Run("the migration labels existing codes by the address they were sent to", func(t *testing.T) {
		up := readRepoFile(t, "internal", "platform", "database", "migrations", "0137_email_verification_purpose.up.sql")
		id, email, _ := newUser(t)
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `ALTER TABLE "user".email_verifications DROP COLUMN purpose`); err != nil {
			t.Fatalf("drop purpose: %v", err)
		}
		for _, addr := range []string{email, "elsewhere-" + email} {
			if _, err := tx.Exec(ctx,
				`INSERT INTO "user".email_verifications (user_id, email, code_hash, expires_at) VALUES ($1, $2, 'x', NOW())`,
				id, addr); err != nil {
				t.Fatalf("seed code row: %v", err)
			}
		}
		if _, err := tx.Exec(ctx, up); err != nil {
			t.Fatalf("apply migration: %v", err)
		}
		purposes := map[string]string{}
		rows, err := tx.Query(ctx, `SELECT email, purpose FROM "user".email_verifications WHERE user_id = $1`, id)
		if err != nil {
			t.Fatalf("read purposes: %v", err)
		}
		for rows.Next() {
			var addr, purpose string
			if err := rows.Scan(&addr, &purpose); err != nil {
				t.Fatalf("scan: %v", err)
			}
			purposes[addr] = purpose
		}
		rows.Close()
		if purposes[email] != "verify_email" || purposes["elsewhere-"+email] != "change_email" {
			t.Fatalf("purposes = %v", purposes)
		}
	})
}
