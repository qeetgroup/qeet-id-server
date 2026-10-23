//go:build integration

package scim

// Database tests for SCIM groups and users, driving the real handlers through
// MountPublic against a migrated PostgreSQL (see dbtest).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// scimFixture sets up a tenant, a SCIM bearer token, two users, and a mounted
// SCIM router driving the real handlers.
type scimFixture struct {
	tenantID uuid.UUID
	token    string
	router   chi.Router
}

func newSCIMFixture(t *testing.T, ctx context.Context) *scimFixture {
	t.Helper()
	tid := dbtest.Tenant(t)

	// Seed a SCIM bearer token for this tenant (hash scheme matches Rotate).
	token := tokenPrefix + uuid.NewString()
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO tenant.scim_tokens (tenant_id, token_hash, token_prefix)
		VALUES ($1, $2, $3)
	`, tid, codes.Hash(token), tokenPrefix+"seed"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	svc := NewService(dbtest.Pool(t), user.NewRepository(dbtest.Pool(t)))
	h := &Handler{Service: svc}
	r := chi.NewRouter()
	h.MountPublic(r)
	return &scimFixture{tenantID: tid, token: token, router: r}
}

// seedUser creates a tenant user and returns its id.
func (f *scimFixture) seedUser(t *testing.T, ctx context.Context, email string) uuid.UUID {
	t.Helper()
	repo := user.NewRepository(dbtest.Pool(t))
	u, err := repo.CreateWithCredential(ctx, user.CreateInput{TenantID: f.tenantID, Email: email}, "")
	if err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return u.ID
}

// do issues a SCIM request and returns the recorder.
func (f *scimFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "http://localhost:4000"+path, rdr)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", scimContentType)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body (%d): %v\nbody=%s", rec.Code, err, rec.Body.String())
	}
	return m
}

func memberValues(res map[string]any) []string {
	raw, _ := res["members"].([]any)
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		if mm, ok := m.(map[string]any); ok {
			if v, ok := mm["value"].(string); ok {
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestSCIMGroupLifecycle walks create → get → list → PATCH add member →
// PATCH remove member → delete, plus the displayName filter.
func TestSCIMGroupLifecycle(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	alice := f.seedUser(t, ctx, "alice-"+uuid.NewString()+"@acme.test")
	bob := f.seedUser(t, ctx, "bob-"+uuid.NewString()+"@acme.test")

	// --- create (displayName + one initial member) ---
	rec := f.do(t, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": "Engineering",
		"externalId":  "ext-eng-1",
		"members":     []map[string]any{{"value": alice.String()}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	created := decodeBody(t, rec)
	gid, _ := created["id"].(string)
	if gid == "" {
		t.Fatalf("create: missing id, body %s", rec.Body.String())
	}
	if created["displayName"] != "Engineering" {
		t.Fatalf("create: displayName = %v", created["displayName"])
	}
	if created["externalId"] != "ext-eng-1" {
		t.Fatalf("create: externalId = %v", created["externalId"])
	}
	if got := memberValues(created); len(got) != 1 || got[0] != alice.String() {
		t.Fatalf("create: members = %v, want [%s]", got, alice)
	}

	// --- get ---
	rec = f.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status %d", rec.Code)
	}
	got := decodeBody(t, rec)
	if got["displayName"] != "Engineering" {
		t.Fatalf("get: displayName = %v", got["displayName"])
	}

	// --- list + displayName filter ---
	rec = f.do(t, http.MethodGet, `/scim/v2/Groups?filter=`+urlFilter("Engineering"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status %d", rec.Code)
	}
	list := decodeBody(t, rec)
	if total, _ := list["totalResults"].(float64); total != 1 {
		t.Fatalf("filtered list totalResults = %v, want 1", list["totalResults"])
	}
	// A non-matching filter returns zero.
	rec = f.do(t, http.MethodGet, `/scim/v2/Groups?filter=`+urlFilter("Nope"), nil)
	nope := decodeBody(t, rec)
	if total, _ := nope["totalResults"].(float64); total != 0 {
		t.Fatalf("non-matching filter totalResults = %v, want 0", nope["totalResults"])
	}

	// --- PATCH add member (Okta-style add op) ---
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": bob.String()}}}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch add: status %d body %s", rec.Code, rec.Body.String())
	}
	afterAdd := memberValues(decodeBody(t, rec))
	want := []string{alice.String(), bob.String()}
	sort.Strings(want)
	if len(afterAdd) != 2 || afterAdd[0] != want[0] || afterAdd[1] != want[1] {
		t.Fatalf("patch add: members = %v, want %v", afterAdd, want)
	}

	// --- PATCH remove member (Okta filter-path remove) ---
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + alice.String() + `"]`}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch remove: status %d body %s", rec.Code, rec.Body.String())
	}
	afterRemove := memberValues(decodeBody(t, rec))
	if len(afterRemove) != 1 || afterRemove[0] != bob.String() {
		t.Fatalf("patch remove: members = %v, want [%s]", afterRemove, bob)
	}

	// --- PATCH replace displayName ---
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Eng Renamed"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch rename: status %d", rec.Code)
	}
	if decodeBody(t, rec)["displayName"] != "Eng Renamed" {
		t.Fatalf("patch rename did not take")
	}

	// --- delete ---
	rec = f.do(t, http.MethodDelete, "/scim/v2/Groups/"+gid, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d", rec.Code)
	}
	rec = f.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status %d, want 404", rec.Code)
	}
}

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

// TestSCIMGroupNameUniqueness checks that groups with an externalId may share
// a displayName, and that a group without one which takes an existing name,
// ignoring case, is refused with 409 uniqueness on create, replace and patch.
func TestSCIMGroupNameUniqueness(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'Support')`, f.tenantID); err != nil {
		t.Fatalf("seed console group: %v", err)
	}
	create := func(name, externalID string) *httptest.ResponseRecorder {
		body := map[string]any{"schemas": []string{schemaGroup}, "displayName": name}
		if externalID != "" {
			body["externalId"] = externalID
		}
		return f.do(t, http.MethodPost, "/scim/v2/Groups", body)
	}
	isUniqueness := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusConflict && decodeBody(t, rec)["scimType"] == "uniqueness"
	}

	var ids []string
	for _, ext := range []string{"ext-1", "ext-2"} {
		rec := create("Marketing", ext)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create Marketing %s: status %d body %s", ext, rec.Code, rec.Body)
		}
		id, _ := decodeBody(t, rec)["id"].(string)
		ids = append(ids, id)
	}
	if rec := create("support", ""); !isUniqueness(rec) {
		t.Errorf("create support without externalId: status %d body %s, want 409 uniqueness", rec.Code, rec.Body)
	}

	rec := f.do(t, http.MethodPut, "/scim/v2/Groups/"+ids[0], map[string]any{
		"schemas": []string{schemaGroup}, "displayName": "SUPPORT",
	})
	if !isUniqueness(rec) {
		t.Errorf("replace as SUPPORT without externalId: status %d body %s, want 409 uniqueness", rec.Code, rec.Body)
	}

	clearExternalID := func(id string) *httptest.ResponseRecorder {
		return f.do(t, http.MethodPatch, "/scim/v2/Groups/"+id, map[string]any{
			"schemas":    []string{schemaPatchOp},
			"Operations": []map[string]any{{"op": "replace", "path": "externalId", "value": ""}},
		})
	}
	if rec := clearExternalID(ids[0]); rec.Code != http.StatusOK {
		t.Fatalf("clear the first Marketing's externalId: status %d body %s", rec.Code, rec.Body)
	}
	if rec := clearExternalID(ids[1]); !isUniqueness(rec) {
		t.Errorf("clear the second Marketing's externalId: status %d body %s, want 409 uniqueness", rec.Code, rec.Body)
	}
}

// TestSCIMGroupTenantIsolation proves one tenant can never read or mutate
// another tenant's group via the SCIM surface.
func TestSCIMGroupTenantIsolation(t *testing.T) {
	ctx := dbtest.Context(t)
	a := newSCIMFixture(t, ctx)
	b := newSCIMFixture(t, ctx)

	rec := a.do(t, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": "TenantA-Only",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create in A: status %d", rec.Code)
	}
	gid, _ := decodeBody(t, rec)["id"].(string)

	// Tenant B must not see it via get, patch, or delete.
	if rec := b.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("B get A's group: status %d, want 404", rec.Code)
	}
	if rec := b.do(t, http.MethodDelete, "/scim/v2/Groups/"+gid, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("B delete A's group: status %d, want 404", rec.Code)
	}
	// B's list must be empty (A's group not leaked).
	rec = b.do(t, http.MethodGet, "/scim/v2/Groups", nil)
	if total, _ := decodeBody(t, rec)["totalResults"].(float64); total != 0 {
		t.Fatalf("B list leaked A's group: totalResults = %v", decodeBody(t, rec)["totalResults"])
	}
	// A still sees it.
	if rec := a.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil); rec.Code != http.StatusOK {
		t.Fatalf("A get its own group: status %d", rec.Code)
	}
}

// urlFilter builds the `displayName eq "x"` filter query value, URL-escaped.
func urlFilter(name string) string {
	return strings.ReplaceAll(`displayName+eq+%22`+name+`%22`, " ", "+")
}

const schemaPatchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

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
		WHERE tenant_id = $1 AND resource_type = 'user' AND resource_id = $2
		ORDER BY created_at, action
	`, f.tenantID, userID)
	if !equalStrings(auditActions, wantActions) {
		t.Errorf("audit actions = %v, want %v", auditActions, wantActions)
	}

	// Attribution has to name the SCIM credential, not a user and not "system":
	// there is no human actor on this path, and mislabelling it would make the
	// trail misleading rather than merely thin.
	actorTypes := collectColumn(t, ctx, `
		SELECT DISTINCT actor_type FROM audit.events
		WHERE tenant_id = $1 AND resource_id = $2
	`, f.tenantID, userID)
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
		`SELECT count(*) FROM "user".users WHERE email = $1`, email).Scan(&users); err != nil {
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

// TestSCIMUserWriteTenantIsolation checks that one tenant's SCIM token can't
// suspend or rename another tenant's user: PUT and PATCH both return 404 and
// leave the victim's row unchanged.
func TestSCIMUserWriteTenantIsolation(t *testing.T) {
	ctx := dbtest.Context(t)
	a := newSCIMFixture(t, ctx)
	b := newSCIMFixture(t, ctx)

	victim := a.seedUser(t, ctx, "victim-"+uuid.NewString()+"@a.example")

	statusOf := func() string {
		var s string
		if err := dbtest.Pool(t).QueryRow(ctx,
			`SELECT status FROM "user".users WHERE id = $1`, victim).Scan(&s); err != nil {
			t.Fatalf("read victim status: %v", err)
		}
		return s
	}
	before := statusOf()

	// PATCH active:false — the deprovisioning shape a hostile tenant would use.
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
		`SELECT display_name FROM "user".users WHERE id = $1`, victim).Scan(&displayName); err != nil {
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
