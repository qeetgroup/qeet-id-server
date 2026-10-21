//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	authhook "github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// hookSkipsCounted reads auth_hook_skipped_total for one reason and outcome.
func hookSkipsCounted(t *testing.T, reason, outcome string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "auth_hook_skipped_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["reason"] == reason && labels["outcome"] == outcome {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// TestASignInHookThatGivesNoAnswerFollowsItsSetting: an organisation can mark
// its sign-in hook fail-closed so no sign-in completes without the hook's
// answer, but when the hook couldn't be read, or its signing secret couldn't
// be opened, the sign-in completed anyway and nothing said the hook was
// skipped. Every case where the hook gives no answer now follows the hook's
// fail-open setting — the last one read, where it can't be read now — and is
// recorded in the audit log and a metric.
func TestASignInHookThatGivesNoAnswerFollowsItsSetting(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	answering := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	t.Cleanup(answering.Close)
	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>maintenance</html>`))
	}))
	t.Cleanup(garbled.Close)
	box := testEnvelope(t)
	newService := func() *authhook.Service {
		svc := authhook.NewService(testPool, egress.DevelopmentPolicy())
		svc.SetCipher(box)
		return svc
	}
	organisation := func(t *testing.T, url string, failOpen bool) (uuid.UUID, uuid.UUID, uuid.UUID) {
		t.Helper()
		tenantID := createTenant(t, ctx, uniqueSlug("hooked"))
		hook, err := newService().Create(ctx, tenantID, url, "hook-signing-secret", failOpen)
		if err != nil {
			t.Fatal(err)
		}
		return tenantID, createUserInTenant(t, ctx, tenantID), hook.ID
	}
	breakSecret := func(t *testing.T, hookID uuid.UUID) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `UPDATE tenant.auth_hooks SET secret_nonce = $2 WHERE id = $1`, hookID, []byte("not-the-nonce")); err != nil {
			t.Fatal(err)
		}
	}
	skipAudited := func(t *testing.T, tenantID uuid.UUID, reason, outcome string) {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `
			SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = 'auth_hook.skipped' AND metadata->>'reason' = $2 AND metadata->>'outcome' = $3`,
			tenantID, reason, outcome).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("auth_hook.skipped audits (reason %s, outcome %s) = %d, want 1", reason, outcome, n)
		}
	}
	refusedUnavailable := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, errs.ErrAuthHookDenied) || errs.As(err).Message != "Sign-in is temporarily unavailable. Please try again later." {
			t.Fatalf("sign-in = %v, want it refused as temporarily unavailable", err)
		}
	}

	t.Run("a fail-closed hook whose secret can't be opened refuses the sign-in", func(t *testing.T) {
		tenantID, userID, hookID := organisation(t, answering.URL, false)
		breakSecret(t, hookID)
		before := hookSkipsCounted(t, "secret_unavailable", "refused")
		_, err := newService().Run(ctx, tenantID, userID, "member@example.com")
		refusedUnavailable(t, err)
		skipAudited(t, tenantID, "secret_unavailable", "refused")
		if hookSkipsCounted(t, "secret_unavailable", "refused") != before+1 {
			t.Fatal("the skip wasn't counted")
		}
	})

	t.Run("without the cipher to open it, a fail-closed hook refuses too", func(t *testing.T) {
		tenantID, userID, _ := organisation(t, answering.URL, false)
		_, err := authhook.NewService(testPool, egress.DevelopmentPolicy()).Run(ctx, tenantID, userID, "member@example.com")
		refusedUnavailable(t, err)
		skipAudited(t, tenantID, "secret_unavailable", "refused")
	})

	t.Run("a fail-closed hook that can't be read refuses the sign-in", func(t *testing.T) {
		tenantID, userID, _ := organisation(t, answering.URL, false)
		svc := newService()
		if _, err := svc.Run(ctx, tenantID, userID, "member@example.com"); err != nil {
			t.Fatalf("sign-in while the hook answers = %v, want allowed", err)
		}
		// Hold the hooks table so reading the hook fails (times out).
		lock, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err := lock.Exec(ctx, `LOCK TABLE tenant.auth_hooks IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		_, err = svc.Run(short, tenantID, userID, "member@example.com")
		_ = lock.Rollback(ctx)
		refusedUnavailable(t, err)
		skipAudited(t, tenantID, "unreadable", "refused")
	})

	t.Run("a fail-open hook that can't be loaded lets the sign-in proceed, recorded", func(t *testing.T) {
		tenantID, userID, hookID := organisation(t, answering.URL, true)
		breakSecret(t, hookID)
		if _, err := newService().Run(ctx, tenantID, userID, "member@example.com"); err != nil {
			t.Fatalf("sign-in = %v, want allowed", err)
		}
		skipAudited(t, tenantID, "secret_unavailable", "allowed")
	})

	t.Run("a hook call that fails or can't be read is recorded too", func(t *testing.T) {
		tenantID, userID, _ := organisation(t, garbled.URL, true)
		if _, err := newService().Run(ctx, tenantID, userID, "member@example.com"); err != nil {
			t.Fatalf("sign-in = %v, want allowed", err)
		}
		skipAudited(t, tenantID, "unparseable", "allowed")

		tenantID, userID, _ = organisation(t, "http://127.0.0.1:1/unreachable", false)
		_, err := newService().Run(ctx, tenantID, userID, "member@example.com")
		refusedUnavailable(t, err)
		skipAudited(t, tenantID, "call_failed", "refused")
	})

	t.Run("a hook that answers is not recorded as skipped", func(t *testing.T) {
		tenantID, userID, _ := organisation(t, answering.URL, false)
		if _, err := newService().Run(ctx, tenantID, userID, "member@example.com"); err != nil {
			t.Fatalf("sign-in = %v, want allowed", err)
		}
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'auth_hook.skipped'`, tenantID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("skips recorded for an answering hook = %d (%v), want 0", n, err)
		}
	})
}
