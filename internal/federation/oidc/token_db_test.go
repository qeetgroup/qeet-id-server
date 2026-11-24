//go:build integration

package oidc

import (
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func registerResources(t *testing.T, svc *Service, organization uuid.UUID, identifiers ...string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	for _, id := range identifiers {
		if _, err := svc.createResource(ctx, tx, organization, CreateResourceInput{Identifier: id, Name: id}); err != nil {
			t.Fatalf("create resource %s: %v", id, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestGrantsRunOnTheirTransaction checks that registering a resource served by
// an application, redeeming a code and refreshing for that resource, and
// approving a device run every query on the transaction they hold.
func TestGrantsRunOnTheirTransaction(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	dbtest.LeaveOneConnection(t)
	svc := newTestService(t, pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	server, _ := registerClient(t, svc, organization)
	client, secret := registerClientWith(t, svc, CreateClientInput{
		OrganizationID: organization, GrantTypes: []string{"authorization_code", "refresh_token", grantTypeDeviceCode},
	})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := svc.createResource(ctx, tx, organization, CreateResourceInput{Identifier: resourceA, Name: "A", ServerClientID: server.ClientID}); err != nil {
		t.Fatalf("create resource: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	issued := redeemCode(t, svc, client, secret, user.ID, resourceA)
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	_, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, nil)
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if err := svc.DecideDevice(ctx, user.ID, userCode, true, deviceIP); err != nil {
		t.Fatalf("approve device: %v", err)
	}
}
