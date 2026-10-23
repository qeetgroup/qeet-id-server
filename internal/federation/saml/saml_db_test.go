//go:build integration

package saml

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	db "github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// TestConnectionUpdateRunsOnItsTransaction checks that Update reads the
// IdP-initiated opt-in on the transaction it is given, so a pool of one
// connection serves it, and reports the stored value.
func TestConnectionUpdateRunsOnItsTransaction(t *testing.T) {
	ctx := dbtest.Context(t)
	pool, err := db.NewPool(ctx, dbtest.DSN(t), 0, 1)
	if err != nil {
		t.Fatalf("one-connection pool: %v", err)
	}
	t.Cleanup(pool.Close)
	svc := NewService(pool, nil, testPublicBase)
	tenant := dbtest.Tenant(t)
	cert, _ := selfSignedCert(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	conn, err := svc.Create(ctx, tx, tenant, CreateInput{
		Name: "IdP", IdpEntityID: "https://idp.example.com", IdpSSOURL: "https://idp.example.com/sso", IdpCertificate: cert,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	allow := true
	if _, err := svc.Update(ctx, tx, conn.ID, tenant, UpdateInput{AllowIdPInitiated: &allow}); err != nil {
		t.Fatalf("allow IdP-initiated: %v", err)
	}
	name := "Renamed"
	got, err := svc.Update(ctx, tx, conn.ID, tenant, UpdateInput{Name: &name})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got.Name != name || !got.AllowIdPInitiated {
		t.Errorf("renamed connection %q, allow_idp_initiated %t; want %q, true", got.Name, got.AllowIdPInitiated, name)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
