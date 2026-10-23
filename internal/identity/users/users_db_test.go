//go:build integration

package user

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestUsersStayInTheirTenant checks that an administrator of one tenant can
// neither read nor change a user who belongs only to another tenant.
func TestUsersStayInTheirTenant(t *testing.T) {
	pool := dbtest.Pool(t)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	victim := dbtest.User(t, tenantA, tenantA)
	adminA := dbtest.User(t, tenantA, tenantA)
	adminB := dbtest.User(t, tenantB, tenantB)

	h := &Handler{
		Repo:           NewRepository(pool),
		Validate:       validator.New(validator.WithRequiredStructEnabled()),
		PasswordPolicy: func(context.Context, uuid.UUID, string, string) error { return nil },
	}
	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), h.Mount)
	path := "/users/" + victim.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, path, nil},
		{http.MethodGet, path + "/security", nil},
		{http.MethodGet, path + "/access", nil},
		{http.MethodPatch, path, map[string]any{"display_name": "changed"}},
		{http.MethodPatch, path, map[string]any{"status": "suspended"}},
		{http.MethodPost, path + "/password", map[string]any{"password": "Kx7mQ2vLp9Wz-other"}},
		{http.MethodPut, path + "/mfa-required", map[string]any{"required": true}},
		{http.MethodDelete, path + "/membership", nil},
		{http.MethodDelete, path, nil},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != http.StatusNotFound {
			t.Errorf("tenant B %s %s: status %d, want 404 (%s)", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/users", nil)); slices.Contains(ids, victim.ID) {
		t.Error("tenant B's user list includes tenant A's user")
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM "user".users
		WHERE id = $1 AND status = 'active' AND deleted_at IS NULL AND display_name IS NULL
	`, victim.ID); n != 1 {
		t.Error("tenant B changed tenant A's user")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.password_credentials WHERE user_id = $1`, victim.ID); n != 0 {
		t.Error("tenant B set a password for tenant A's user")
	}

	asA := dbtest.Serve(dbtest.Principal(adminA.ID, tenantA), h.Mount)
	if rec := dbtest.Do(t, asA, http.MethodGet, path, nil); rec.Code != http.StatusOK {
		t.Fatalf("tenant A reads its own user: status %d", rec.Code)
	}
}

// TestEmptyUpdateReadsThroughTheTransaction checks that an update that sets
// nothing returns the user as the caller's transaction sees it.
func TestEmptyUpdateReadsThroughTheTransaction(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	tenant := dbtest.Tenant(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	created, err := repo.CreateWithCredentialTx(ctx, tx, CreateInput{TenantID: tenant, Email: dbtest.Unique("user") + "@example.test"}, "")
	if err != nil {
		t.Fatalf("create in the transaction: %v", err)
	}

	got, err := repo.UpdateTx(ctx, tx, created.ID, UpdateInput{})
	if err != nil || got.ID != created.ID {
		t.Fatalf("empty update in the transaction that created the user: %+v, %v", got, err)
	}
}
