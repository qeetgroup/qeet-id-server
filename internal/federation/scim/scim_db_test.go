//go:build integration

package scim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// planGate includes SCIM in the plans of the tenants it holds.
type planGate map[uuid.UUID]bool

func (g planGate) FeatureAllowed(_ context.Context, tenantID uuid.UUID, _ string) (bool, error) {
	return g[tenantID], nil
}

// TestLapsedPlanStopsSCIM checks that a SCIM token issued while the plan
// included SCIM provisions nothing once the plan has lapsed.
func TestLapsedPlanStopsSCIM(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	plans := planGate{f.tenantID: true}
	f.svc.SetPlanGate(plans)
	if rec := f.do(t, http.MethodGet, "/scim/v2/Users", nil); rec.Code != http.StatusOK {
		t.Fatalf("SCIM on a plan with it: status %d", rec.Code)
	}

	delete(plans, f.tenantID) // the plan lapses
	rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": dbtest.Unique("new") + "@example.test",
	})
	if rec.Code != http.StatusForbidden || decodeBody(t, rec)["schemas"] == nil {
		t.Errorf("SCIM after the plan lapsed: status %d %s, want a SCIM 403", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE tenant_id = $1`, f.tenantID); n != 0 {
		t.Errorf("%d users provisioned after the plan lapsed, want none", n)
	}
}

// TestSCIMUserReadsStayInTheirTenant checks that one tenant's SCIM token can
// neither find, read nor delete another tenant's user.
func TestSCIMUserReadsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	a := newSCIMFixture(t, ctx)
	b := newSCIMFixture(t, ctx)
	email := dbtest.Unique("victim") + "@a.example.test"
	victim := a.seedUser(t, ctx, email)

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/scim/v2/Users/" + victim.String(), http.StatusNotFound},
		{http.MethodDelete, "/scim/v2/Users/" + victim.String(), http.StatusNotFound},
	} {
		if rec := b.do(t, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("B %s %s: status %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
	for _, path := range []string{"/scim/v2/Users", "/scim/v2/Users?filter=" + url.QueryEscape(`userName eq "`+email+`"`)} {
		if total := decodeBody(t, b.do(t, http.MethodGet, path, nil))["totalResults"]; total != float64(0) {
			t.Errorf("B GET %s: totalResults %v, want 0", path, total)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND deleted_at IS NULL`, victim); n != 1 {
		t.Error("B's SCIM token deleted A's user")
	}
	if rec := a.do(t, http.MethodGet, "/scim/v2/Users/"+victim.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("A reads its own user: status %d", rec.Code)
	}
}

// TestSCIMAdoptingAnUnverifiedAccountRemovesItsCredentials checks that the
// directory vouching for an account nobody vouched for, however it does
// (creating, replacing or patching it), leaves nothing whoever registered the
// address set up and records it, while an account that proved its address, or
// one the directory already provisioned, keeps everything.
func TestSCIMAdoptingAnUnverifiedAccountRemovesItsCredentials(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSCIMFixture(t, ctx)
	domain := dbtest.Domain(t, f.tenantID)
	account := func(setup string) dbtest.Account {
		t.Helper()
		a := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+domain, f.tenantID, f.tenantID)
		dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz-squat")
		for _, q := range []string{
			`INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, name) SELECT id, convert_to(id::text, 'UTF8'), '\x00', 'Laptop' FROM account.users WHERE id = $1`,
			`INSERT INTO auth.mfa_totp (user_id, secret_ct, secret_nonce, confirmed_at) VALUES ($1, '\x00', '\x00', NOW())`,
			`INSERT INTO auth.api_keys (tenant_id, user_id, name, prefix, key_hash) SELECT tenant_id, id, 'laptop', left(md5(id::text), 12), 'hash' FROM account.users WHERE id = $1`,
			`INSERT INTO auth.sessions (user_id, tenant_id) SELECT id, tenant_id FROM account.users WHERE id = $1`,
			setup,
		} {
			if _, err := pool.Exec(ctx, q, a.ID); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		return a
	}
	held := func(a dbtest.Account) int {
		return dbtest.Count(t, `SELECT (SELECT count(*) FROM auth.password_credentials WHERE user_id = $1)
			+ (SELECT count(*) FROM auth.passkey_credentials WHERE user_id = $1)
			+ (SELECT count(*) FROM auth.mfa_totp WHERE user_id = $1)
			+ (SELECT count(*) FROM auth.api_keys WHERE user_id = $1 AND revoked_at IS NULL)
			+ (SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL)`, a.ID)
	}
	ok := func(what string, rec *httptest.ResponseRecorder, want int) {
		t.Helper()
		if rec.Code != want {
			t.Fatalf("%s: %d %s", what, rec.Code, rec.Body.String())
		}
	}
	patch := func(a dbtest.Account, path, value string) *httptest.ResponseRecorder {
		return f.do(t, http.MethodPatch, "/scim/v2/Users/"+a.ID.String(), map[string]any{"schemas": []string{schemaPatchOp},
			"Operations": []map[string]any{{"op": "replace", "path": path, "value": value}}})
	}
	// Each way the directory comes to vouch for an account that already exists.
	ways := map[string]func(a dbtest.Account){
		"a create that adopts it": func(a dbtest.Account) {
			ok("adopt", f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": a.Email, "active": true}), http.StatusCreated)
		},
		"a replace": func(a dbtest.Account) {
			ok("replace", f.do(t, http.MethodPut, "/scim/v2/Users/"+a.ID.String(), map[string]any{
				"schemas": []string{schemaUser}, "userName": a.Email, "externalId": dbtest.Unique("ext"), "active": true}), http.StatusOK)
		},
		"a patch of its external id": func(a dbtest.Account) {
			ok("patch externalId", patch(a, "externalId", dbtest.Unique("ext")), http.StatusOK)
		},
		"a patch of its address": func(a dbtest.Account) {
			ok("patch userName", patch(a, "userName", dbtest.Unique("alice.k")+"@"+domain), http.StatusOK)
		},
	}
	for way, vouch := range ways {
		squatted := account(`SELECT $1::uuid`)
		vouch(squatted)
		if n := held(squatted); n != 0 {
			t.Errorf("%s: an account nobody vouched for keeps %d of its 5 credentials and sessions, want none", way, n)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.credentials_removed' AND resource_id = $1
			AND tenant_id = $2 AND metadata->>'proof' = 'scim_adoption'`, squatted.ID, f.tenantID); n != 1 {
			t.Errorf("%s: the removal was recorded %d times, want once", way, n)
		}
		for name, setup := range map[string]string{
			"an account that proved its address":           `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`,
			"an account the directory already provisioned": `UPDATE account.users SET provisioned_via = 'scim' WHERE id = $1`,
		} {
			a := account(setup)
			vouch(a)
			if n := held(a); n != 5 {
				t.Errorf("%s: %s keeps %d of its 5 credentials and sessions, want all", way, name, n)
			}
		}
	}
}

// TestSCIMDoesNotChangeAnAdministratorsAddress checks that the directory can't
// move an account that administers the organisation to a new address, by PATCH
// or by PUT, as single sign-on doesn't, so that account's password reset keeps
// going to its holder; a member's address still moves.
func TestSCIMDoesNotChangeAnAdministratorsAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	domain := dbtest.Domain(t, f.tenantID)
	provision := func() (string, string) {
		t.Helper()
		email := dbtest.Unique("asha") + "@" + domain
		rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": email, "active": true})
		id, _ := decodeBody(t, rec)["id"].(string)
		if rec.Code != http.StatusCreated || id == "" {
			t.Fatalf("provision %s: %d %s", email, rec.Code, rec.Body.String())
		}
		return id, email
	}
	address := func(id string) string {
		t.Helper()
		var email string
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT email FROM account.users WHERE id = $1`, id).Scan(&email); err != nil {
			t.Fatal(err)
		}
		return email
	}
	patch := func(id, email string) int {
		return f.do(t, http.MethodPatch, "/scim/v2/Users/"+id, map[string]any{"schemas": []string{schemaPatchOp},
			"Operations": []map[string]any{{"op": "replace", "path": "userName", "value": email}}}).Code
	}
	put := func(id, email string) int {
		return f.do(t, http.MethodPut, "/scim/v2/Users/"+id, map[string]any{"schemas": []string{schemaUser}, "userName": email, "active": true}).Code
	}

	admin, adminEmail := provision()
	dbtest.Assign(t, uuid.MustParse(admin), f.tenantID, dbtest.Role(t, f.tenantID, "user.write"))
	for verb, change := range map[string]func(id, email string) int{"PATCH": patch, "PUT": put} {
		if code := change(admin, dbtest.Unique("asha+x")+"@"+domain); code != http.StatusForbidden {
			t.Errorf("%s an administrator's userName: %d, want 403", verb, code)
		}
	}
	if got := address(admin); got != adminEmail {
		t.Errorf("the administrator's address moved to %s", got)
	}

	member, _ := provision()
	moved := dbtest.Unique("asha.k") + "@" + domain
	if code := patch(member, moved); code != http.StatusOK || address(member) != moved {
		t.Errorf("PATCH a member's userName: %d, address %s; want 200 and %s", code, address(member), moved)
	}
}

// TestSCIMDeprovisioningListsTheIntegrationsTheUserCreated checks that
// deleting a user through the directory records, as an administrator's
// deletion does, the critical event listing the integrations they created.
func TestSCIMDeprovisioningListsTheIntegrationsTheUserCreated(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	id := f.seedUser(t, ctx, dbtest.Unique("scim")+"@example.test")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO tenant.webhook_subscriptions (tenant_id, url, secret_ct, secret_nonce, created_by)
		VALUES ($1, 'https://hooks.example.test/in', '\x00', '\x00', $2)`, f.tenantID, id); err != nil {
		t.Fatal(err)
	}
	if rec := f.do(t, http.MethodDelete, "/scim/v2/Users/"+id.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'user.integrations_left'
		AND resource_id = $2 AND actor_type = 'scim' AND metadata->'integrations'->0->>'kind' = 'webhook'`, f.tenantID, id); n != 1 {
		t.Errorf("%d events listing the deprovisioned user's webhook, want 1", n)
	}
}
