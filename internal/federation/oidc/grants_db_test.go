//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// TestGrantRevocationKeepsItsAuditRow checks that revoking a grant commits
// with an audit row naming who revoked it, and that the grant stays when the
// row can't be written.
func TestGrantRevocationKeepsItsAuditRow(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	admin, asha, ravi := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	actor := audit.Actor{UserID: &admin.ID, Type: "user", IP: "192.0.2.42", RequestID: "req-" + uuid.NewString()}
	app, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Name: "Reports"})
	redeemCode(t, svc, app, secret, asha.ID, "")
	redeemCode(t, svc, app, secret, ravi.ID, "")
	grantOf := func(user uuid.UUID) uuid.UUID {
		t.Helper()
		page, err := svc.ListGrants(ctx, organization, nil, 0, paging.Cursor{})
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range page.Items {
			if g.UserID == user {
				return g.ID
			}
		}
		return uuid.Nil
	}

	if err := svc.RevokeGrant(ctx, organization, grantOf(asha.ID), actor); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if grantOf(asha.ID) != uuid.Nil {
		t.Error("Asha's grant is still active")
	}
	if n := recordedBy(t, organization, "oauth.grant_revoked", asha.ID, actor); n != 1 {
		t.Errorf("%d oauth.grant_revoked rows by the administrator, want 1", n)
	}

	refuseAudit(t, organization, "oauth.grant_revoked")
	if err := svc.RevokeGrant(ctx, organization, grantOf(ravi.ID), actor); err == nil {
		t.Error("a grant was revoked without its audit row")
	}
	if grantOf(ravi.ID) == uuid.Nil {
		t.Error("the revocation stayed when its audit row failed")
	}
}

// TestGrantAdministration checks that an organization's admin sees the live
// grants its people have given applications and can end one, every rotation
// included, and can neither see nor end another organization's.
func TestGrantAdministration(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	person := dbtest.User(t, organization, organization)
	outsider := dbtest.User(t, otherOrganization, otherOrganization)
	h := (&Handler{Service: svc}).Mount
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h)
	asOutsider := dbtest.Serve(dbtest.Principal(outsider.ID, otherOrganization), h)
	client, secret := registerClient(t, svc, organization)
	first := redeemCode(t, svc, client, secret, person.ID, "")
	rotated, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	grants := "/organizations/" + organization.String() + "/oauth/grants"

	var page struct {
		Items []Grant `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, grants, nil), &page)
	if len(page.Items) != 1 || page.Items[0].ClientID != client.ClientID || page.Items[0].UserEmail != person.Email {
		t.Fatalf("grants %+v, want the person's one live grant", page.Items)
	}
	grant := page.Items[0].ID.String()
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, grants, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organization listing the grants: %d, want 403", rec.Code)
	}
	inOther := "/organizations/" + otherOrganization.String() + "/oauth/grants/" + grant
	if rec := dbtest.Do(t, asOutsider, http.MethodDelete, inOther, nil); !strings.Contains(rec.Body.String(), CodeGrantNotFound) {
		t.Errorf("another organization ending the grant: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, grants+"/"+grant, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("end the grant: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, rotated.RefreshToken, ""); !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Errorf("refresh after the grant ended: %v, want %v", err, ErrRefreshTokenRevoked)
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, grants, nil)); len(ids) != 0 {
		t.Errorf("grants after ending it %v, want none", ids)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'oauth.grant_revoked' AND resource_id = $2`, organization, person.ID); n != 1 {
		t.Errorf("ending the grant was audited %d times, want once", n)
	}
}

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

	page, err := svc.ListGrants(ctx, organization, nil, 2, paging.Cursor{})
	if err != nil || page.Total != 3 || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first page: %+v, %v; want 2 of 3 with a cursor", page, err)
	}
	rest, err := svc.ListGrants(ctx, organization, nil, 2, cursorOf(t, page.NextCursor))
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
	if only, err := svc.ListGrants(ctx, organization, &app.ClientID, 0, paging.Cursor{}); err != nil || only.Total != 2 || len(only.Items) != 2 {
		t.Errorf("the application's grants: %+v, %v; want its two", only, err)
	}

	system := audit.Actor{Type: "system"}
	if n, err := svc.RevokeGrants(ctx, other, []uuid.UUID{refreshed.ID}, "", system); err != nil || n != 0 {
		t.Errorf("revoke from another organization: %d, %v; want none", n, err)
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
	if left, err := svc.ListGrants(ctx, organization, nil, 0, paging.Cursor{}); err != nil || left.Total != 1 || left.Items[0].UserID != ravi.ID {
		t.Errorf("left after revoking: %+v, %v; want only Ravi's", left, err)
	}
}

// cursorOf is the page cursor a list's next_cursor names.
func cursorOf(t *testing.T, next string) paging.Cursor {
	t.Helper()
	c, err := paging.ParseCursor(url.Values{"cursor": {next}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
