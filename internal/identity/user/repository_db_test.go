//go:build integration

package user

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestEmptyUpdateReadsThroughTheTransaction checks that an update that sets
// nothing returns the user as the caller's transaction sees it.
func TestEmptyUpdateReadsThroughTheTransaction(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	organization := dbtest.Organization(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	created, err := repo.CreateWithCredentialTx(ctx, tx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("user") + "@example.test"}, "")
	if err != nil {
		t.Fatalf("create in the transaction: %v", err)
	}

	got, err := repo.UpdateTx(ctx, tx, created.ID, UpdateInput{})
	if err != nil || got.ID != created.ID {
		t.Fatalf("empty update in the transaction that created the user: %+v, %v", got, err)
	}
}
