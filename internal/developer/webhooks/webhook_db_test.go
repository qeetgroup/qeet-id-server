//go:build integration

package webhook

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestWebhooksStayInTheirTenant checks that one tenant can neither read nor
// change another tenant's webhook subscription or its deliveries, and that its
// events are never delivered to it.
func TestWebhooksStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := NewService(pool)
	svc.SetCipher(box)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminB := dbtest.User(t, tenantB, tenantB)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	subA, err := svc.Create(ctx, tx, CreateInput{TenantID: tenantA, URL: "https://hooks.example.test/a", Events: []string{"user.created"}})
	if err != nil {
		t.Fatalf("create subscription in A: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := svc.Enqueue(ctx, tenantA, "user.created", map[string]any{"n": 1}); err != nil {
		t.Fatalf("enqueue in A: %v", err)
	}
	var deliveryA uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tenant.webhook_deliveries WHERE subscription_id = $1`, subA.ID).Scan(&deliveryA); err != nil {
		t.Fatalf("delivery in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc}).Mount)
	path := "/webhooks/" + subA.ID.String()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, path, http.StatusNotFound},
		{http.MethodPost, path + "/test", http.StatusNotFound},
		{http.MethodPost, path + "/deliveries/" + deliveryA.String() + "/retry", http.StatusNotFound},
		{http.MethodDelete, path, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/webhooks", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, path+"/deliveries", nil)); len(ids) != 0 {
		t.Errorf("tenant B sees %d of tenant A's deliveries", len(ids))
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/webhooks", nil)); slices.Contains(ids, subA.ID) {
		t.Error("tenant B's subscription list includes tenant A's")
	}

	if err := svc.Enqueue(ctx, tenantB, "user.created", map[string]any{"n": 2}); err != nil {
		t.Fatalf("enqueue in B: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.webhook_deliveries WHERE subscription_id = $1`, subA.ID); n != 1 {
		t.Errorf("tenant A's subscription has %d deliveries, want only its own 1", n)
	}
	if got, err := svc.Get(ctx, subA.ID, tenantA); err != nil || got.DisabledAt != nil {
		t.Errorf("tenant A's subscription after tenant B's calls: %+v, %v", got, err)
	}
}
