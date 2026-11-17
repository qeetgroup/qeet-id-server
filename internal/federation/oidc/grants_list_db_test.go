//go:build integration

package oidc

import (
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestGrantsNameTheirPartiesPageAndRevokeTogether checks that a grant names
// its application and person and tells when it began from when it was last
// used, that the list pages and filters by application, and that several
// grants, or an application's every grant, are revoked in one call, in their
// organization only.
func TestGrantsNameTheirPartiesPageAndRevokeTogether(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	asha, ravi := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	app, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Name: "Reports"})
	crm, crmSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Name: "CRM"})

	first := redeemCode(t, svc, app, secret, asha.ID, "")
	if _, err := svc.RefreshToken(ctx, app.ClientID, secret, first.RefreshToken, ""); err != nil {
		t.Fatal(err)
	}
	redeemCode(t, svc, app, secret, ravi.ID, "")
	redeemCode(t, svc, crm, crmSecret, asha.ID, "")

	page, err := svc.ListGrants(ctx, organization, nil, 2, "")
	if err != nil || page.Total != 3 || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first page: %+v, %v; want 2 of 3 with a cursor", page, err)
	}
	rest, err := svc.ListGrants(ctx, organization, nil, 2, page.NextCursor)
	if err != nil || len(rest.Items) != 1 || rest.NextCursor != "" {
		t.Fatalf("second page: %+v, %v; want the last one", rest, err)
	}
	var refreshed *Grant
	for _, g := range append(page.Items, rest.Items...) {
		if g.ClientName == "" || g.UserEmail == "" {
			t.Errorf("grant %+v: want its application's name and its person's email", g)
		}
		if g.UserID == asha.ID && g.ClientID == app.ClientID {
			refreshed = &g
		}
	}
	if refreshed == nil || refreshed.ClientName != "Reports" || !refreshed.LastUsedAt.After(refreshed.AuthorizedAt) {
		t.Errorf("the refreshed grant %+v: want Reports, last used after it began", refreshed)
	}
	if only, err := svc.ListGrants(ctx, organization, &app.ClientID, 0, ""); err != nil || only.Total != 2 || len(only.Items) != 2 {
		t.Errorf("the application's grants: %+v, %v; want its two", only, err)
	}

	system := audit.Actor{Type: "system"}
	if n, err := svc.RevokeGrants(ctx, other, []uuid.UUID{refreshed.ID}, "", system); err != nil || n != 0 {
		t.Errorf("revoke from another tenant: %d, %v; want none", n, err)
	}
	if n, err := svc.RevokeGrants(ctx, organization, []uuid.UUID{refreshed.ID, uuid.New()}, "", system); err != nil || n != 1 {
		t.Errorf("revoke one known and one unknown grant: %d, %v; want 1", n, err)
	}
	if n, err := svc.RevokeGrants(ctx, organization, nil, crm.ClientID, system); err != nil || n != 1 {
		t.Errorf("revoke the CRM's grants: %d, %v; want 1", n, err)
	}
	if _, err := svc.RevokeGrants(ctx, organization, []uuid.UUID{refreshed.ID}, crm.ClientID, system); err == nil {
		t.Error("a revocation naming both grants and an application was accepted")
	}
	if left, err := svc.ListGrants(ctx, organization, nil, 0, ""); err != nil || left.Total != 1 || left.Items[0].UserID != ravi.ID {
		t.Errorf("left after revoking: %+v, %v; want only Ravi's", left, err)
	}
}
