//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	siemdb "github.com/qeetgroup/qeet-id-server/internal/operations/siem/dbgen"
)

// trailEvent is one audit event as an organisation's trail shows it.
type trailEvent struct {
	TenantID   *uuid.UUID
	Actor      *uuid.UUID
	ActorType  string
	Resource   *uuid.UUID
	IP         string
	Metadata   map[string]any
	RawPayload string
}

func trailEvents(t *testing.T, ctx context.Context, where string, args ...any) []trailEvent {
	t.Helper()
	rows, err := testPool.Query(ctx, `
		SELECT tenant_id, actor_user_id, actor_type, resource_id, COALESCE(host(ip), ''), COALESCE(metadata, '{}'::jsonb),
		       row_to_json(e)::text
		FROM audit.events e WHERE `+where+` ORDER BY created_at, id`, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []trailEvent
	for rows.Next() {
		var e trailEvent
		var meta []byte
		if err := rows.Scan(&e.TenantID, &e.Actor, &e.ActorType, &e.Resource, &e.IP, &meta, &e.RawPayload); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(meta, &e.Metadata)
		out = append(out, e)
	}
	return out
}

// TestFailedSignInsAndRecoveryRequestsReachTheOrganisationsTrail: an
// organisation's audit trail, and the log stream built on it, recorded
// successful sign-ins only — not wrong passwords, wrong second-factor codes,
// failed passkeys, lockouts or password-reset requests — and a completed reset
// was recorded with no organisation, so a credential-stuffing run against an
// organisation was invisible to it. Each is now recorded under the
// organisation, naming the account (or no one, for an address with no
// account), the reason and the source, never what was submitted; and the
// records are bounded so an attack can't flood the trail.
func TestFailedSignInsAndRecoveryRequestsReachTheOrganisationsTrail(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	post := func(path, ip string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "trail-test")
		req.RemoteAddr = ip + ":40000"
		rr := httptest.NewRecorder()
		f.router.ServeHTTP(rr, req)
		return rr
	}
	failures := func(t *testing.T, tenantID uuid.UUID, method string) []trailEvent {
		t.Helper()
		return trailEvents(t, ctx, `tenant_id = $1 AND action = 'auth.sign_in_failed' AND metadata->>'method' = $2`, tenantID, method)
	}
	names := func(e trailEvent, userID uuid.UUID) bool {
		return e.Actor != nil && *e.Actor == userID && e.Resource != nil && *e.Resource == userID
	}

	t.Run("a wrong password names the account, the organisation, the reason and the source", func(t *testing.T) {
		id, email := f.member(t, ctx)
		const attempted = "Not-the-passphrase-7"
		if rr := post("/v1/auth/login", "198.51.100.10", map[string]string{"email": email, "password": attempted}); rr.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password = %d %s", rr.Code, rr.Body.String())
		}
		got := failures(t, f.tenantID, "password")
		if len(got) != 1 || !names(got[0], id) || got[0].Metadata["reason"] != "wrong_password" ||
			got[0].IP != "198.51.100.10" || got[0].Metadata["network"] != "198.51.100.10" {
			t.Fatalf("records = %+v, want one naming the account, wrong_password and the source", got)
		}
		if strings.Contains(got[0].RawPayload, attempted) {
			t.Fatal("the record carries the submitted password")
		}
	})

	t.Run("an unknown address is recorded naming no person", func(t *testing.T) {
		address := uniqueSlug("nobody") + "@example.com"
		if rr := post("/v1/auth/login", "198.51.100.11", map[string]string{"email": address, "password": "Any-passphrase-8"}); rr.Code != http.StatusUnauthorized {
			t.Fatalf("unknown address = %d", rr.Code)
		}
		got := trailEvents(t, ctx, `action = 'auth.sign_in_failed' AND host(ip) = '198.51.100.11'`)
		if len(got) != 1 || got[0].Actor != nil || got[0].Resource != nil || got[0].ActorType != "anonymous" ||
			got[0].Metadata["reason"] != "unknown_account" || strings.Contains(got[0].RawPayload, address) {
			t.Fatalf("records = %+v, want one naming no person", got)
		}
	})

	t.Run("a wrong second-factor code is recorded", func(t *testing.T) {
		id, email := f.member(t, ctx)
		secret := f.holdTOTP(t, ctx, id)
		rr := post("/v1/auth/login", "198.51.100.12", map[string]string{"email": email, "password": factorPassword})
		var c challenge
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &c) != nil || c.MFAToken == "" {
			t.Fatalf("password step = %d %s", rr.Code, rr.Body.String())
		}
		wrong := []byte(totpCodeAtStep(t, secret, 0))
		wrong[0] = '0' + (wrong[0]-'0'+1)%10
		if rr := post("/v1/auth/mfa", "198.51.100.12", map[string]any{"mfa_token": c.MFAToken, "code": string(wrong)}); rr.Code == http.StatusOK {
			t.Fatalf("a wrong code = %d, want refused", rr.Code)
		}
		got := failures(t, f.tenantID, "mfa")
		var mine []trailEvent
		for _, e := range got {
			if names(e, id) {
				mine = append(mine, e)
			}
		}
		if len(mine) != 1 || mine[0].Metadata["reason"] != "code_invalid" || mine[0].IP != "198.51.100.12" {
			t.Fatalf("records = %+v, want one code_invalid naming the account", mine)
		}
	})

	t.Run("a passkey sign-in that fails verification is recorded", func(t *testing.T) {
		id, _ := f.member(t, ctx)
		rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
		a := virtualwebauthn.NewAuthenticator()
		registered := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		sid, creation, err := f.passkeys.BeginRegister(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		creationJSON, _ := json.Marshal(creation)
		opts, err := virtualwebauthn.ParseAttestationOptions(string(creationJSON))
		if err != nil {
			t.Fatal(err)
		}
		a.Options.UserHandle = []byte(opts.UserID)
		if err := f.passkeys.FinishRegister(ctx, id, sid, json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, a, registered, *opts)), "Laptop", "test"); err != nil {
			t.Fatal(err)
		}
		loginSID, assertion, err := f.passkeys.BeginLogin(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		assertionJSON, _ := json.Marshal(assertion)
		aopts, err := virtualwebauthn.ParseAssertionOptions(string(assertionJSON))
		if err != nil {
			t.Fatal(err)
		}
		// Signed by a key the account never registered.
		forged := virtualwebauthn.CreateAssertionResponse(rp, a, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *aopts)
		if _, err := f.passkeys.FinishLogin(ctx, loginSID, json.RawMessage(forged), "198.51.100.13", "trail-test"); err == nil {
			t.Fatal("a forged assertion signed in")
		}
		got := failures(t, f.tenantID, "passkey")
		if len(got) != 1 || !names(got[0], id) || got[0].Metadata["reason"] != "passkey.login_failed" || got[0].IP != "198.51.100.13" {
			t.Fatalf("records = %+v, want one passkey.login_failed naming the account", got)
		}
	})

	t.Run("a lock is recorded with when it lifts, and attempts against it too", func(t *testing.T) {
		id, email := f.member(t, ctx)
		for range 5 {
			post("/v1/auth/login", "198.51.100.14", map[string]string{"email": email, "password": "Not-the-passphrase-9"})
		}
		if rr := post("/v1/auth/login", "198.51.100.14", map[string]string{"email": email, "password": factorPassword}); rr.Code == http.StatusOK {
			t.Fatal("a locked account signed in")
		}
		locks := trailEvents(t, ctx, `tenant_id = $1 AND action = 'auth.account_locked' AND resource_id = $2`, f.tenantID, id)
		if len(locks) != 1 || locks[0].Metadata["locked_until"] == nil || locks[0].Metadata["counter"] != "account_network" {
			t.Fatalf("lock records = %+v, want one with locked_until", locks)
		}
		until, err := time.Parse(time.RFC3339, locks[0].Metadata["locked_until"].(string))
		if err != nil || !until.After(time.Now()) {
			t.Fatalf("locked_until = %v (%v), want a time to come", locks[0].Metadata["locked_until"], err)
		}
		var refused int
		for _, e := range failures(t, f.tenantID, "password") {
			if names(e, id) && e.Metadata["reason"] == "account_locked" {
				refused++
			}
		}
		if refused != 1 {
			t.Fatalf("attempts against the lock recorded = %d, want 1", refused)
		}
	})

	t.Run("a password reset requested and completed reaches the trail and the log stream", func(t *testing.T) {
		id, email := f.member(t, ctx)
		if rr := post("/v1/auth/forgot-password", "198.51.100.15", map[string]string{"email": email}); rr.Code != http.StatusOK {
			t.Fatalf("forgot = %d", rr.Code)
		}
		m, ok := f.mail.last()
		token := regexp.MustCompile(`token=([^&\s"]+)`).FindStringSubmatch(m.Body)
		if !ok || token == nil {
			t.Fatalf("no reset link was sent: %q", m.Body)
		}
		raw, _ := url.QueryUnescape(token[1])
		if rr := post("/v1/auth/reset-password", "198.51.100.15", map[string]string{"token": raw, "new_password": "A-brand-new-passphrase-3"}); rr.Code != http.StatusOK {
			t.Fatalf("reset = %d %s", rr.Code, rr.Body.String())
		}
		for _, action := range []string{"auth.password_reset_requested", "auth.password_reset_confirmed"} {
			if got := trailEvents(t, ctx, `tenant_id = $1 AND action = $2 AND resource_id = $3`, f.tenantID, action, id); len(got) != 1 {
				t.Fatalf("%s in the organisation's trail = %d, want 1", action, len(got))
			}
		}
		streamed, err := siemdb.New(testPool).FetchAuditEventsAfterCursor(ctx, siemdb.FetchAuditEventsAfterCursorParams{
			TenantID: pgtype.UUID{Bytes: f.tenantID, Valid: true}, AfterAt: time.Now().Add(-time.Hour), AfterID: uuid.Nil, RowLimit: 1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, e := range streamed {
			if e.ResourceID == (pgtype.UUID{Bytes: id, Valid: true}) {
				seen[e.Action] = true
			}
		}
		if !seen["auth.password_reset_requested"] || !seen["auth.password_reset_confirmed"] {
			t.Fatalf("the log stream carries %v, want the reset's request and completion", seen)
		}
	})

	t.Run("a magic-link request is recorded", func(t *testing.T) {
		id, email := f.member(t, ctx)
		f.hostedLink(t, email)
		if got := trailEvents(t, ctx, `tenant_id = $1 AND action = 'auth.magic_link_requested' AND resource_id = $2`, f.tenantID, id); len(got) != 1 {
			t.Fatalf("magic-link requests recorded = %d, want 1", len(got))
		}
	})

	t.Run("one source can't flood the trail", func(t *testing.T) {
		for range 30 {
			post("/v1/auth/login", "198.51.100.16", map[string]string{"email": uniqueSlug("spray") + "@example.com", "password": "Any-passphrase-8"})
		}
		if got := trailEvents(t, ctx, `action = 'auth.sign_in_failed' AND host(ip) = '198.51.100.16'`); len(got) == 0 || len(got) > 20 {
			t.Fatalf("records from one source = %d, want some and at most 20", len(got))
		}
	})
}
