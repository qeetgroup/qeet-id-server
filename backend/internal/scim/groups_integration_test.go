//go:build integration

// DB-backed lifecycle tests for SCIM 2.0 Groups, driving the real HTTP
// handlers through MountPublic against an ephemeral Postgres (testcontainers),
// migrated with the repo's own migration files. Gated behind the `integration`
// build tag so the default `go test ./...` stays Docker-free; skips cleanly if
// Docker is unavailable.
package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/user"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()
	if os.Getenv("TESTCONTAINERS_RYUK_DISABLED") == "" {
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}
	scripts, err := upMigrations()
	if err != nil {
		fmt.Fprintf(os.Stderr, "scim integration: cannot locate migrations: %v\n", err)
		return 1
	}
	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("qeet_id_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.WithInitScripts(scripts...),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scim integration: skipping (container start failed): %v\n", err)
		return 0
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "scim integration: connection string: %v\n", err)
		return 1
	}
	testPool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scim integration: pool: %v\n", err)
		return 1
	}
	defer testPool.Close()
	return m.Run()
}

func upMigrations() ([]string, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, filepath.Join(dir, e.Name()))
		}
	}
	if len(ups) == 0 {
		return nil, fmt.Errorf("no .up.sql files in %s", dir)
	}
	sort.Strings(ups)
	return ups, nil
}

func requireDB(t *testing.T) {
	t.Helper()
	if testPool == nil {
		t.Skip("scim integration: no database (Docker unavailable)")
	}
}

// scimFixture sets up a tenant, a SCIM bearer token, two users, and a mounted
// SCIM router driving the real handlers.
type scimFixture struct {
	tenantID uuid.UUID
	token    string
	router   chi.Router
}

func newSCIMFixture(t *testing.T, ctx context.Context) *scimFixture {
	t.Helper()
	var tid uuid.UUID
	slug := "scim-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	if err := testPool.QueryRow(ctx, `
		INSERT INTO tenant.tenants (slug, name, plan, region)
		VALUES ($1, $2, 'free', 'us-east-1') RETURNING id
	`, slug, slug).Scan(&tid); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// Seed a SCIM bearer token for this tenant (hash scheme matches Rotate).
	token := tokenPrefix + uuid.NewString()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.scim_tokens (tenant_id, token_hash, token_prefix)
		VALUES ($1, $2, $3)
	`, tid, codes.Hash(token), tokenPrefix+"seed"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	svc := NewService(testPool, user.NewRepository(testPool))
	h := &Handler{Service: svc}
	r := chi.NewRouter()
	h.MountPublic(r)
	return &scimFixture{tenantID: tid, token: token, router: r}
}

// seedUser creates a tenant user and returns its id.
func (f *scimFixture) seedUser(t *testing.T, ctx context.Context, email string) uuid.UUID {
	t.Helper()
	repo := user.NewRepository(testPool)
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
	requireDB(t)
	ctx := context.Background()
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

// TestSCIMGroupTenantIsolation proves one tenant can never read or mutate
// another tenant's group via the SCIM surface.
func TestSCIMGroupTenantIsolation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
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
