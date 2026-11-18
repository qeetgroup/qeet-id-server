//go:build integration

package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestSCIMUserFilterAndUnfilteredPagination(t *testing.T) {
	ctx := dbtest.Context(t)
	fixture := newSCIMFixture(t, ctx)
	firstEmail := "first-" + uuid.NewString() + "@acme.test"
	secondEmail := "second-" + uuid.NewString() + "@acme.test"
	for _, email := range []string{firstEmail, secondEmail} {
		recorder := fixture.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{
			"schemas": []string{schemaUser}, "userName": email, "active": true,
		})
		if recorder.Code != http.StatusCreated {
			t.Fatalf("create SCIM user %s: status %d body %s", email, recorder.Code, recorder.Body.String())
		}
	}

	exact := fixture.do(t, http.MethodGet, `/scim/v2/Users?filter=`+url.QueryEscape(`userName eq "`+firstEmail+`"`), nil)
	if exact.Code != http.StatusOK {
		t.Fatalf("exact user filter status = %d: %s", exact.Code, exact.Body.String())
	}
	exactBody := decodeBody(t, exact)
	if exactBody["totalResults"] != float64(1) {
		t.Fatalf("exact user filter totalResults = %v, want 1", exactBody["totalResults"])
	}

	unfiltered := fixture.do(t, http.MethodGet, "/scim/v2/Users?startIndex=1&count=1", nil)
	if unfiltered.Code != http.StatusOK {
		t.Fatalf("unfiltered user list status = %d: %s", unfiltered.Code, unfiltered.Body.String())
	}
	unfilteredBody := decodeBody(t, unfiltered)
	if unfilteredBody["totalResults"] != float64(2) || unfilteredBody["itemsPerPage"] != float64(1) {
		t.Fatalf("unfiltered pagination = total %v page %v, want 2/1", unfilteredBody["totalResults"], unfilteredBody["itemsPerPage"])
	}

	invalid := fixture.do(t, http.MethodGet, `/scim/v2/Users?filter=`+url.QueryEscape(`emails.value eq "`+firstEmail+`"`), nil)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("unsupported user filter status = %d, want 400", invalid.Code)
	}
	invalidBody := decodeBody(t, invalid)
	if invalidBody["scimType"] != "invalidFilter" {
		t.Fatalf("unsupported user filter scimType = %v", invalidBody["scimType"])
	}
}

// TestSCIMUserMutationsEmitAtomicEvidence checks that SCIM user create,
// replace, patch and delete each write an audit row and a domain event.
func TestSCIMUserMutationsEmitAtomicEvidence(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)

	email := "evidence-" + uuid.NewString()[:8] + "@example.com"
	rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName": email, "displayName": "Evidence User", "active": true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d, body %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created user: %v", err)
	}
	userID := uuid.MustParse(created.ID)

	// Deactivate via PATCH — the deprovisioning shape IdPs actually use.
	rec = f.do(t, http.MethodPatch, "/scim/v2/Users/"+created.ID, map[string]any{
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch user = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = f.do(t, http.MethodDelete, "/scim/v2/Users/"+created.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete user = %d, body %s", rec.Code, rec.Body.String())
	}

	wantActions := []string{"user.created", "user.updated", "user.deleted"}

	auditActions := collectColumn(t, ctx, `
		SELECT action FROM audit.events
		WHERE organization_id = $1 AND resource_type = 'user' AND resource_id = $2
		ORDER BY created_at, action
	`, f.organizationID, userID)
	if !equalStrings(auditActions, wantActions) {
		t.Errorf("audit actions = %v, want %v", auditActions, wantActions)
	}

	// Attribution has to name the SCIM credential, not a user and not "system":
	// there is no human actor on this path, and mislabelling it would make the
	// trail misleading rather than merely thin.
	actorTypes := collectColumn(t, ctx, `
		SELECT DISTINCT actor_type FROM audit.events
		WHERE organization_id = $1 AND resource_id = $2
	`, f.organizationID, userID)
	if len(actorTypes) != 1 || actorTypes[0] != "scim" {
		t.Errorf("actor types = %v, want [scim]", actorTypes)
	}

	outboxTypes := collectColumn(t, ctx, `
		SELECT event_type FROM platform.outbox
		WHERE aggregate_id = $1 AND topic = 'user.events'
		ORDER BY created_at, event_type
	`, userID)
	if !equalStrings(outboxTypes, wantActions) {
		t.Errorf("outbox event types = %v, want %v", outboxTypes, wantActions)
	}
}

// TestSCIMCreateRollsBackWithoutEvidence proves the write is atomic rather than
// merely accompanied: with the audit table refusing inserts, the user must not
// exist afterwards.
func TestSCIMCreateRollsBackWithoutEvidence(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)

	owner := dbtest.Owner(t)
	if _, err := owner.Exec(ctx, `
		CREATE OR REPLACE FUNCTION scim_audit_block() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'audit write blocked'; END; $$ LANGUAGE plpgsql;
		CREATE TRIGGER scim_audit_block_trg BEFORE INSERT ON audit.events
		FOR EACH ROW EXECUTE FUNCTION scim_audit_block();
	`); err != nil {
		t.Fatalf("install audit trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `DROP TRIGGER IF EXISTS scim_audit_block_trg ON audit.events`)
	})

	email := "rollback-" + uuid.NewString()[:8] + "@example.com"
	rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": email, "active": true})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create with blocked audit = %d, want 500", rec.Code)
	}
	var users int
	if err := dbtest.Pool(t).QueryRow(ctx,
		`SELECT count(*) FROM account.users WHERE email = $1`, email).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Errorf("user rows = %d, want 0 — the mutation committed without its evidence", users)
	}
}

func collectColumn(t *testing.T, ctx context.Context, sql string, args ...any) []string {
	t.Helper()
	rows, err := dbtest.Pool(t).Query(ctx, sql, args...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, v)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSCIMUserWriteOrganizationIsolation checks that one organization's SCIM token can't
// suspend or rename another organization's user: PUT and PATCH both return 404 and
// leave the victim's row unchanged.
func TestSCIMUserWriteOrganizationIsolation(t *testing.T) {
	ctx := dbtest.Context(t)
	a := newSCIMFixture(t, ctx)
	b := newSCIMFixture(t, ctx)

	victim := a.seedUser(t, ctx, "victim-"+uuid.NewString()+"@a.example")

	statusOf := func() string {
		var s string
		if err := dbtest.Pool(t).QueryRow(ctx,
			`SELECT status FROM account.users WHERE id = $1`, victim).Scan(&s); err != nil {
			t.Fatalf("read victim status: %v", err)
		}
		return s
	}
	before := statusOf()

	// PATCH active:false — the deprovisioning shape a hostile organization would use.
	rec := b.do(t, http.MethodPatch, "/scim/v2/Users/"+victim.String(), map[string]any{
		"schemas": []string{schemaPatchOp},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": false},
		},
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("B PATCH A's user: status %d, want 404", rec.Code)
	}
	if got := statusOf(); got != before {
		t.Errorf("B's PATCH mutated A's user: status %q -> %q", before, got)
	}

	// PUT replace — same hole, different verb.
	rec = b.do(t, http.MethodPut, "/scim/v2/Users/"+victim.String(), map[string]any{
		"schemas":     []string{schemaUser},
		"userName":    "pwned@b.example",
		"displayName": "pwned",
		"active":      false,
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("B PUT A's user: status %d, want 404", rec.Code)
	}
	if got := statusOf(); got != before {
		t.Errorf("B's PUT mutated A's user: status %q -> %q", before, got)
	}

	var displayName *string
	if err := dbtest.Pool(t).QueryRow(ctx,
		`SELECT display_name FROM account.users WHERE id = $1`, victim).Scan(&displayName); err != nil {
		t.Fatalf("read victim display_name: %v", err)
	}
	if displayName != nil && *displayName == "pwned" {
		t.Error("B's PUT overwrote A's user display_name")
	}

	// A's own token must still work, so the guard scopes rather than blocks.
	if rec := a.do(t, http.MethodPatch, "/scim/v2/Users/"+victim.String(), map[string]any{
		"schemas": []string{schemaPatchOp},
		"Operations": []map[string]any{
			{"op": "replace", "path": "displayName", "value": "renamed-by-owner"},
		},
	}); rec.Code != http.StatusOK {
		t.Fatalf("A PATCH its own user: status %d, want 200", rec.Code)
	}
}

// TestSCIMCreatesNoAccountOnAnotherOrganizationsDomain checks that a
// directory provisions no account on a domain another organization has
// verified, and still provisions its own.
func TestSCIMCreatesNoAccountOnAnotherOrganizationsDomain(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	theirs := dbtest.Domain(t, dbtest.Organization(t))
	claimed := dbtest.Unique("scim") + "@" + theirs
	if rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": claimed, "active": true}); rec.Code != http.StatusConflict {
		t.Errorf("provision on another organization's domain: %d %s, want 409", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, claimed); n != 0 {
		t.Errorf("the account was created")
	}
	own := dbtest.Unique("scim") + "@" + dbtest.Domain(t, f.organizationID)
	if rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": own, "active": true}); rec.Code != http.StatusCreated {
		t.Errorf("provision on the organization's domain: %d %s, want 201", rec.Code, rec.Body.String())
	}
}

// TestSCIMDeprovisioningEndsEverySignIn checks that deactivating or deleting
// a user through SCIM ends their sessions, remembered devices and application
// grants, as an administrator's suspension does.
func TestSCIMDeprovisioningEndsEverySignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSCIMFixture(t, ctx)
	signedIn := func() uuid.UUID {
		t.Helper()
		id := f.seedUser(t, ctx, dbtest.Unique("scim")+"@example.test")
		if _, err := pool.Exec(ctx, `
			WITH s AS (INSERT INTO auth.sessions (user_id, organization_id) VALUES ($1, $2)),
			     d AS (INSERT INTO auth.trusted_devices (user_id, organization_id, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 day'))
			INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at)
			VALUES ($4, 'app', $1, $2, NOW() + INTERVAL '1 day')
		`, id, f.organizationID, dbtest.Unique("device"), dbtest.Unique("grant")); err != nil {
			t.Fatal(err)
		}
		return id
	}
	live := func(id uuid.UUID) int {
		return dbtest.Count(t, `
			SELECT (SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL)
			     + (SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1)
			     + (SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL)
		`, id)
	}

	deactivated, deleted := signedIn(), signedIn()
	if rec := f.do(t, http.MethodPatch, "/scim/v2/Users/"+deactivated.String(), map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("deactivate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, http.MethodDelete, "/scim/v2/Users/"+deleted.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	for name, id := range map[string]uuid.UUID{"deactivated": deactivated, "deleted": deleted} {
		if n := live(id); n != 0 {
			t.Errorf("a %s user kept %d ways in", name, n)
		}
	}
}

// TestSCIMMatchesAndAdoptsMembers checks that a userName lookup finds a
// member the directory didn't create, that creating them adopts that account
// rather than refusing a duplicate, and that someone at home elsewhere is
// still refused.
func TestSCIMMatchesAndAdoptsMembers(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	domain := dbtest.Domain(t, f.organizationID)
	member := f.seedUser(t, ctx, dbtest.Unique("invited")+"@"+domain)
	var email string
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT email FROM account.users WHERE id = $1`, member).Scan(&email); err != nil {
		t.Fatal(err)
	}
	found := decodeBody(t, f.do(t, http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "`+strings.ToUpper(email)+`"`), nil))
	if found["totalResults"] != float64(1) {
		t.Errorf("lookup by userName: %v; want the member", found)
	}
	if all := decodeBody(t, f.do(t, http.MethodGet, "/scim/v2/Users", nil)); all["totalResults"] != float64(0) {
		t.Errorf("unfiltered list: %v; want only directory-provisioned accounts", all)
	}

	rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": email, "externalId": "okta-77", "displayName": "Ada Lovelace", "active": true})
	if rec.Code != http.StatusCreated || decodeBody(t, rec)["id"] != member.String() {
		t.Fatalf("create the member: %d %s; want 201 with the existing account", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND provisioned_via = 'scim' AND external_id = 'okta-77' AND display_name = 'Ada Lovelace'`, member); n != 1 {
		t.Error("the adopted account was not tagged and updated")
	}

	guest := dbtest.UserAt(t, dbtest.Unique("guest")+"@"+domain, dbtest.Organization(t))
	if rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": guest.Email, "active": true}); rec.Code != http.StatusConflict {
		t.Errorf("create someone at home elsewhere: %d %s, want 409", rec.Code, rec.Body.String())
	}
}

// TestSCIMUserReadsStayInTheirOrganization checks that one organization's SCIM token can
// neither find, read nor delete another organization's user.
func TestSCIMUserReadsStayInTheirOrganization(t *testing.T) {
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

// TestSCIMDeprovisioningListsTheIntegrationsTheUserCreated checks that
// deleting a user through the directory records, as an administrator's
// deletion does, the critical event listing the integrations they created.
func TestSCIMDeprovisioningListsTheIntegrationsTheUserCreated(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	id := f.seedUser(t, ctx, dbtest.Unique("scim")+"@example.test")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO organization.webhook_subscriptions (organization_id, url, secret_ct, secret_nonce, created_by)
		VALUES ($1, 'https://hooks.example.test/in', '\x00', '\x00', $2)`, f.organizationID, id); err != nil {
		t.Fatal(err)
	}
	if rec := f.do(t, http.MethodDelete, "/scim/v2/Users/"+id.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'user.integrations_left'
		AND resource_id = $2 AND actor_type = 'scim' AND metadata->'integrations'->0->>'kind' = 'webhook'`, f.organizationID, id); n != 1 {
		t.Errorf("%d events listing the deprovisioned user's webhook, want 1", n)
	}
}

// refuseAudit makes recording action in organization fail until t ends, so a
// test can check that the change the row describes rolls back with it.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	owner, ctx := dbtest.Owner(t), dbtest.Context(t)
	name := "refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, ddl := range []string{
		`CREATE FUNCTION public.` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$`,
		`CREATE TRIGGER ` + name + ` BEFORE INSERT ON audit.events FOR EACH ROW
		 WHEN (NEW.organization_id = '` + organization.String() + `' AND NEW.action = '` + action + `')
		 EXECUTE FUNCTION public.` + name + `()`,
	} {
		if _, err := owner.Exec(ctx, ddl); err != nil {
			t.Fatalf("refuse %s: %v", action, err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit.events`)
		_, _ = owner.Exec(context.Background(), `DROP FUNCTION public.`+name+`()`)
	})
}

// TestProvisioningChangesKeepTheirEvidence checks that the directory creating,
// suspending and removing an account each commit with their audit row, as the
// directory, and that none of them is kept when that row can't be written.
func TestProvisioningChangesKeepTheirEvidence(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, user.NewRepository(pool))
	organization := dbtest.Organization(t)
	directory := audit.Actor{Type: "scim", IP: "192.0.2.51", RequestID: "req-" + uuid.NewString()}
	recorded := func(action string, userID uuid.UUID) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3
			AND actor_type = 'scim' AND actor_user_id IS NULL AND host(ip) = $4 AND request_id = $5`,
			organization, action, userID, directory.IP, directory.RequestID)
	}
	status := func(userID uuid.UUID) string {
		var s string
		if err := pool.QueryRow(ctx, `SELECT status || CASE WHEN deleted_at IS NULL THEN '' ELSE ',deleted' END FROM account.users WHERE id = $1`, userID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	asha, err := svc.createProvisioned(ctx, directory, organization, newUser{email: dbtest.Unique("asha") + "@example.test", active: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n := recorded("user.created", asha); n != 1 {
		t.Errorf("%d user.created rows by the directory, want 1", n)
	}
	suspended := "suspended"
	if err := svc.applyUserChange(ctx, directory, organization, asha, userChange{in: user.UpdateInput{Status: &suspended}}, "user.updated"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if status(asha) != "suspended" || recorded("user.updated", asha) != 1 {
		t.Errorf("after suspending: %s with %d user.updated rows, want suspended with 1", status(asha), recorded("user.updated", asha))
	}

	ravi, err := svc.createProvisioned(ctx, directory, organization, newUser{email: dbtest.Unique("ravi") + "@example.test", active: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, action := range []string{"user.created", "user.updated", "user.deleted"} {
		refuseAudit(t, organization, action)
	}
	unrecorded := dbtest.Unique("unrecorded") + "@example.test"
	if _, err := svc.createProvisioned(ctx, directory, organization, newUser{email: unrecorded, active: true}); err == nil {
		t.Error("an account was provisioned without its audit row")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, unrecorded); n != 0 {
		t.Error("the provisioned account stayed when its audit row failed")
	}
	if err := svc.applyUserChange(ctx, directory, organization, ravi, userChange{in: user.UpdateInput{Status: &suspended}}, "user.updated"); err == nil {
		t.Error("an account was suspended without its audit row")
	}
	if status(ravi) != "active" {
		t.Errorf("Ravi is %s, want the suspension rolled back", status(ravi))
	}
	if err := svc.deprovision(ctx, directory, organization, ravi); err == nil {
		t.Error("an account was removed without its audit row")
	}
	if status(ravi) != "active" {
		t.Errorf("Ravi is %s, want the removal rolled back", status(ravi))
	}
}
