//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/domains/federation/oidc"
	"github.com/qeetgroup/qeet-id/platform/password"
)

// beginTx opens a transaction for the service-layer admin mutations (which take
// a pgx.Tx like RegisterClient does), failing the test if it can't.
func beginTx(t *testing.T, ctx context.Context) pgx.Tx {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	return tx
}

func commitTx(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
}

// TestOIDCClientLifecycle drives the tenant-scoped client admin surface end to
// end at the service layer: register → list → get → patch → rotate-secret (new
// secret authenticates, old one is rejected) → delete.
func TestOIDCClientLifecycle(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("cli"))
	svc := oidc.NewService(testPool, mustIssuer())

	client, secret := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")
	if secret == "" {
		t.Fatal("confidential client should mint a secret")
	}

	// List: the new client appears, scoped to the tenant.
	list, err := svc.ListClients(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != client.ID {
		t.Fatalf("list = %+v, want exactly the registered client", list)
	}

	// Get by row id.
	got, err := svc.GetClient(ctx, tenantID, client.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientID != client.ClientID {
		t.Errorf("get client_id = %q, want %q", got.ClientID, client.ClientID)
	}

	// Patch: change name + scopes; redirect_uris left nil → unchanged.
	newName := "Renamed RP"
	newScopes := []string{"openid", "email"}
	tx := beginTx(t, ctx)
	upd, err := svc.UpdateClient(ctx, tx, tenantID, client.ID, oidc.UpdateClientInput{
		Name:   &newName,
		Scopes: &newScopes,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	commitTx(t, ctx, tx)
	if upd.Name != newName {
		t.Errorf("name = %q, want %q", upd.Name, newName)
	}
	if strings.Join(upd.Scopes, " ") != "openid email" {
		t.Errorf("scopes = %v, want [openid email]", upd.Scopes)
	}
	if len(upd.RedirectURIs) != 1 || upd.RedirectURIs[0] != "https://app.example/cb" {
		t.Errorf("redirect_uris should be unchanged by partial patch, got %v", upd.RedirectURIs)
	}

	// Rotate secret: the new secret authenticates; the old one no longer does.
	tx = beginTx(t, ctx)
	newSecret, _, err := svc.RotateClientSecret(ctx, tx, tenantID, client.ID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	commitTx(t, ctx, tx)
	if newSecret == "" || newSecret == secret {
		t.Fatalf("rotate-secret should mint a fresh secret (got %q, old %q)", newSecret, secret)
	}
	// The new secret validates against the stored hash; the old one no longer
	// does (the rotate replaced client_secret_hash, reusing register's hashing).
	if !clientSecretValid(t, ctx, client.ClientID, newSecret) {
		t.Error("new secret should validate against the stored hash")
	}
	if clientSecretValid(t, ctx, client.ClientID, secret) {
		t.Error("old secret must NOT validate after rotation")
	}

	// Delete: returns the client_id and the row disappears.
	tx = beginTx(t, ctx)
	deletedClientID, err := svc.DeleteClient(ctx, tx, tenantID, client.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	commitTx(t, ctx, tx)
	if deletedClientID != client.ClientID {
		t.Errorf("delete returned %q, want %q", deletedClientID, client.ClientID)
	}
	if _, err := svc.GetClient(ctx, tenantID, client.ID); err == nil {
		t.Error("get after delete should fail")
	}
}

// TestOIDCClientCrossTenantIsolation proves tenant B can neither see nor mutate
// tenant A's client.
func TestOIDCClientCrossTenantIsolation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("isoA"))
	tenantB := createTenant(t, ctx, uniqueSlug("isoB"))
	svc := oidc.NewService(testPool, mustIssuer())

	clientA, _ := registerOIDCClient(t, ctx, svc, tenantA, "https://a.example/cb")

	// B's list does not include A's client.
	bList, err := svc.ListClients(ctx, tenantB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	for _, c := range bList {
		if c.ID == clientA.ID {
			t.Fatal("tenant B must not see tenant A's client in its list")
		}
	}

	// B cannot GET A's client.
	if _, err := svc.GetClient(ctx, tenantB, clientA.ID); err == nil {
		t.Error("tenant B must not GET tenant A's client")
	}

	// B cannot PATCH A's client (no row in B's scope → ErrNotFound).
	name := "hijacked"
	tx := beginTx(t, ctx)
	if _, err := svc.UpdateClient(ctx, tx, tenantB, clientA.ID, oidc.UpdateClientInput{Name: &name}); err == nil {
		t.Error("tenant B must not PATCH tenant A's client")
	}
	_ = tx.Rollback(ctx)

	// B cannot ROTATE A's client secret.
	tx = beginTx(t, ctx)
	if _, _, err := svc.RotateClientSecret(ctx, tx, tenantB, clientA.ID); err == nil {
		t.Error("tenant B must not rotate tenant A's client secret")
	}
	_ = tx.Rollback(ctx)

	// B cannot DELETE A's client.
	tx = beginTx(t, ctx)
	if _, err := svc.DeleteClient(ctx, tx, tenantB, clientA.ID); err == nil {
		t.Error("tenant B must not DELETE tenant A's client")
	}
	_ = tx.Rollback(ctx)

	// A's client is still intact.
	if _, err := svc.GetClient(ctx, tenantA, clientA.ID); err != nil {
		t.Errorf("tenant A's client should still exist: %v", err)
	}
}

// TestOIDCRotatePublicClientRejected proves rotate-secret is rejected (422) for
// a public client, which has no secret.
func TestOIDCRotatePublicClientRejected(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pub"))
	svc := oidc.NewService(testPool, mustIssuer())

	tx := beginTx(t, ctx)
	pub, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "SPA", Type: "public",
		RedirectURIs: []string{"https://spa.example/cb"},
	})
	if err != nil {
		t.Fatalf("register public: %v", err)
	}
	commitTx(t, ctx, tx)
	if secret != "" {
		t.Fatal("public client must not mint a secret")
	}

	tx = beginTx(t, ctx)
	if _, _, err := svc.RotateClientSecret(ctx, tx, tenantID, pub.ID); err == nil {
		t.Fatal("rotate-secret on a public client must be rejected")
	}
	_ = tx.Rollback(ctx)
}

// clientSecretValid reports whether plaintext authenticates against the stored
// client_secret_hash for the given client_id.
func clientSecretValid(t *testing.T, ctx context.Context, clientID, plaintext string) bool {
	t.Helper()
	var hash *string
	if err := testPool.QueryRow(ctx,
		`SELECT client_secret_hash FROM auth.oidc_clients WHERE client_id = $1`, clientID).Scan(&hash); err != nil {
		t.Fatalf("read secret hash: %v", err)
	}
	if hash == nil {
		return false
	}
	return password.Verify(*hash, plaintext)
}
