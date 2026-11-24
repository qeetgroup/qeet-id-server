//go:build integration

package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestSCIMLeavesOwnersAndOthersSuspensionsAlone checks that a directory can
// neither change nor delete an account that owns the organization, and that
// reactivating someone lifts only a suspension it set itself.
func TestSCIMLeavesOwnersAndOthersSuspensionsAlone(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSCIMFixture(t, ctx)
	active := func(id uuid.UUID, on bool) *httptest.ResponseRecorder {
		t.Helper()
		return f.do(t, http.MethodPatch, "/scim/v2/Users/"+id.String(), map[string]any{
			"schemas":    []string{schemaPatchOp},
			"Operations": []map[string]any{{"op": "replace", "path": "active", "value": on}},
		})
	}
	status := func(id uuid.UUID) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx, `SELECT status FROM account.users WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	owner := f.seedUser(t, ctx, dbtest.Unique("owner")+"@example.test")
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, f.organizationID).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, owner, f.organizationID, ownerRole)
	if rec := active(owner, false); rec.Code != http.StatusForbidden || status(owner) != "active" {
		t.Errorf("deactivate an owner: %d %s, status %s; want 403 and still active", rec.Code, rec.Body.String(), status(owner))
	}
	if rec := f.do(t, http.MethodDelete, "/scim/v2/Users/"+owner.String(), nil); rec.Code != http.StatusForbidden {
		t.Errorf("delete an owner: %d %s, want 403", rec.Code, rec.Body.String())
	}

	byAdmin := f.seedUser(t, ctx, dbtest.Unique("held")+"@example.test")
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, byAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET suspension_source = 'manual' WHERE id = $1`, byAdmin); err != nil {
		t.Fatal(err)
	}
	if rec := active(byAdmin, true); rec.Code != http.StatusOK || status(byAdmin) != "suspended" {
		t.Errorf("reactivate an administrator's suspension: %d, status %s; want it to stand", rec.Code, status(byAdmin))
	}

	byDirectory := f.seedUser(t, ctx, dbtest.Unique("left")+"@example.test")
	if rec := active(byDirectory, false); rec.Code != http.StatusOK || status(byDirectory) != "suspended" {
		t.Fatalf("deactivate: %d, status %s", rec.Code, status(byDirectory))
	}
	if rec := active(byDirectory, true); rec.Code != http.StatusOK || status(byDirectory) != "active" {
		t.Errorf("reactivate the directory's own suspension: %d, status %s; want active", rec.Code, status(byDirectory))
	}
}

// TestSCIMPatchAppliesIdentityAttributes checks that a PATCH applies active
// sent as a string, name parts, externalId and a new userName on the
// organization's domain, refuses one elsewhere, and that a PUT changes the
// address too.
func TestSCIMPatchAppliesIdentityAttributes(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSCIMFixture(t, ctx)
	domain := dbtest.Domain(t, f.organizationID)
	rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": dbtest.Unique("grace") + "@" + domain, "active": true})
	id, _ := decodeBody(t, rec)["id"].(string)
	if rec.Code != http.StatusCreated || id == "" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	patch := func(ops ...map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		return f.do(t, http.MethodPatch, "/scim/v2/Users/"+id, map[string]any{"schemas": []string{schemaPatchOp}, "Operations": ops})
	}
	row := func() (status, email, display, external string, verified bool) {
		t.Helper()
		if err := pool.QueryRow(ctx, `
			SELECT status, email, COALESCE(display_name, ''), COALESCE(external_id, ''), email_verified_at IS NOT NULL
			FROM account.users WHERE id = $1`, id).Scan(&status, &email, &display, &external, &verified); err != nil {
			t.Fatal(err)
		}
		return
	}

	if rec := patch(map[string]any{"op": "Replace", "path": "active", "value": "False"}); rec.Code != http.StatusOK {
		t.Fatalf("deactivate with a string: %d %s", rec.Code, rec.Body.String())
	}
	if status, _, _, _, _ := row(); status != "suspended" {
		t.Errorf("after active \"False\": %s, want suspended", status)
	}
	moved := dbtest.Unique("grace.hopper") + "@" + domain
	if rec := patch(
		map[string]any{"op": "replace", "value": map[string]any{"active": "True", "externalId": "entra-9"}},
		map[string]any{"op": "replace", "path": "name.givenName", "value": "Grace"},
		map[string]any{"op": "replace", "path": "name.familyName", "value": "Hopper"},
		map[string]any{"op": "replace", "path": "userName", "value": moved},
	); rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	if status, email, display, external, verified := row(); status != "active" || email != moved || display != "Grace Hopper" || external != "entra-9" || !verified {
		t.Errorf("after the patch: %s %s %q %s verified=%v; want active, the new address verified, the name and the external ID", status, email, display, external, verified)
	}
	if rec := patch(map[string]any{"op": "replace", "path": "userName", "value": dbtest.Unique("grace") + "@elsewhere.example.test"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a userName off the organization's domains: %d %s, want 400", rec.Code, rec.Body.String())
	}
	again := dbtest.Unique("hopper") + "@" + domain
	if rec := f.do(t, http.MethodPut, "/scim/v2/Users/"+id, map[string]any{"userName": again, "displayName": "Grace Hopper", "active": true}); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if _, email, _, _, _ := row(); email != again {
		t.Errorf("after the put: %s, want %s", email, again)
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
	domain := dbtest.Domain(t, f.organizationID)
	account := func(setup string) dbtest.Account {
		t.Helper()
		a := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+domain, f.organizationID, f.organizationID)
		dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz-squat")
		for _, q := range []string{
			`INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, name) SELECT id, convert_to(id::text, 'UTF8'), '\x00', 'Laptop' FROM account.users WHERE id = $1`,
			`INSERT INTO auth.mfa_totp (user_id, secret_ct, secret_nonce, confirmed_at) VALUES ($1, '\x00', '\x00', NOW())`,
			`INSERT INTO auth.api_keys (organization_id, user_id, name, prefix, key_hash) SELECT organization_id, id, 'laptop', left(md5(id::text), 12), 'hash' FROM account.users WHERE id = $1`,
			`INSERT INTO auth.sessions (user_id, organization_id) SELECT id, organization_id FROM account.users WHERE id = $1`,
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
			AND organization_id = $2 AND metadata->>'proof' = 'scim_adoption'`, squatted.ID, f.organizationID); n != 1 {
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
// move an account that administers the organization to a new address, by PATCH
// or by PUT, as single sign-on doesn't, so that account's password reset keeps
// going to its holder; a member's address still moves.
func TestSCIMDoesNotChangeAnAdministratorsAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	domain := dbtest.Domain(t, f.organizationID)
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
	dbtest.Assign(t, uuid.MustParse(admin), f.organizationID, dbtest.Role(t, f.organizationID, "user.write"))
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
