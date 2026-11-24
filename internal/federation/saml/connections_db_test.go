//go:build integration

package saml

// Database tests for the admin routes managing an organization's IdP
// connections and the service providers its IdP serves.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// TestConnectionUpdateRunsOnItsTransaction checks that Update reads the
// IdP-initiated opt-in on the transaction it is given, so a pool of one
// connection serves it, and reports the stored value.
func TestConnectionUpdateRunsOnItsTransaction(t *testing.T) {
	ctx := dbtest.Context(t)
	pool, err := postgres.NewPool(ctx, dbtest.DSN(t), 0, 1)
	if err != nil {
		t.Fatalf("one-connection pool: %v", err)
	}
	t.Cleanup(pool.Close)
	svc := newTestService(t, pool, newAuthService(t), func(d *Deps) { d.AppBaseURL = testPublicBase })
	organization := dbtest.Organization(t)
	cert, _ := selfSignedCert(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	conn, err := svc.create(ctx, tx, organization, CreateInput{
		Name: "IdP", IdpEntityID: "https://idp.example.com", IdpSSOURL: "https://idp.example.com/sso", IdpCertificate: cert,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	allow := true
	if _, err := svc.update(ctx, tx, conn.ID, organization, UpdateInput{AllowIdPInitiated: &allow}); err != nil {
		t.Fatalf("allow IdP-initiated: %v", err)
	}
	name := "Renamed"
	got, err := svc.update(ctx, tx, conn.ID, organization, UpdateInput{Name: &name})
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

// TestAConnectionIsNamedBeforeItsIdP checks that a connection can be created
// with a name alone, as a draft whose addresses and metadata go to the IdP
// first, and that it is turned on only once the IdP's details are added.
func TestAConnectionIsNamedBeforeItsIdP(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := &Handler{Service: newTestService(t, dbtest.Pool(t), newAuthService(t)), PublicBaseURL: testPublicBase}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	public := chi.NewRouter()
	h.MountPublic(public)
	base := "/organizations/" + organization.String() + "/saml"

	if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": "Okta", "status": "active"}); !strings.Contains(rec.Body.String(), CodeConnectionIncomplete) {
		t.Errorf("create an active connection with no IdP: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionIncomplete)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": "Okta", "idp_entity_id": "https://idp.example.test"}); !strings.Contains(rec.Body.String(), CodeConnectionFieldsRequired) {
		t.Errorf("create with only some of the IdP's details: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionFieldsRequired)
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": " Okta "})
	var draft struct {
		Connection
		SPAddresses
	}
	dbtest.Decode(t, rec, &draft)
	if rec.Code != http.StatusCreated || draft.Name != "Okta" || draft.Status != "draft" || len(draft.Certificates) != 0 ||
		draft.ACSURL != acsURL(testPublicBase, draft.ID) || draft.EntityID != spEntityID(testPublicBase, draft.ID) || draft.SPAddresses.MetadataURL == "" {
		t.Fatalf("create with a name alone: %d %s; want a draft with its addresses", rec.Code, rec.Body.String())
	}
	if meta := dbtest.Do(t, public, http.MethodGet, "/saml/metadata/"+draft.ID.String(), nil); meta.Code != http.StatusOK || !strings.Contains(meta.Body.String(), draft.ACSURL) {
		t.Errorf("the draft's metadata: %d %s", meta.Code, meta.Body.String())
	}

	path := base + "/" + draft.ID.String()
	active := map[string]any{"status": "active"}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, active); !strings.Contains(rec.Body.String(), CodeConnectionIncomplete) {
		t.Errorf("turn on the draft with no IdP: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionIncomplete)
	}
	cert, _ := selfSignedCert(t)
	details := map[string]any{"idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso", "idp_certificate": cert}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, details); rec.Code != http.StatusOK {
		t.Fatalf("add the IdP's details: %d %s", rec.Code, rec.Body.String())
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, active)
	var on Connection
	dbtest.Decode(t, rec, &on)
	if rec.Code != http.StatusOK || on.Status != "active" || len(on.Certificates) != 1 {
		t.Errorf("turn on the completed connection: %d %s", rec.Code, rec.Body.String())
	}
}

// refuseAudit makes recording action in organization fail until t ends, so a
// test can check that the change the row describes rolls back with it.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	owner, ctx := dbtest.Owner(t), dbtest.Context(t)
	name := "refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, ddl := range []string{
		`CREATE FUNCTION public.` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$`,
		`CREATE TRIGGER ` + name + ` BEFORE INSERT ON audit.events FOR EACH ROW
		 WHEN (NEW.organization_id = '` + organization.String() + `' AND NEW.action = '` + action + `')
		 EXECUTE FUNCTION public.` + name + `()`,
	} {
		if _, err := owner.Exec(ctx, ddl); err != nil {
			t.Fatalf("refuse %s: %v", action, err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit.events`)
		_, _ = owner.Exec(context.Background(), `DROP FUNCTION public.`+name+`()`)
	})
}

// TestTrustChangesKeepTheirAuditRow checks that changing what a connection
// trusts (its IdP's entity ID, another certificate) commits with an audit row
// naming who changed it, on one connection, and is not kept when that row
// can't be written.
func TestTrustChangesKeepTheirAuditRow(t *testing.T) {
	ctx := dbtest.Context(t)
	pool, err := postgres.NewPool(ctx, dbtest.DSN(t), 0, 1)
	if err != nil {
		t.Fatalf("one-connection pool: %v", err)
	}
	t.Cleanup(pool.Close)
	svc := newTestService(t, pool, newAuthService(t), func(d *Deps) { d.AppBaseURL = testPublicBase })
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	actor := audit.Actor{UserID: &admin.ID, Type: "user", IP: "192.0.2.61", RequestID: "req-" + uuid.NewString()}
	recorded := func(action string, id uuid.UUID) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3
			AND actor_user_id = $4 AND host(ip) = $5 AND request_id = $6`, organization, action, id, admin.ID, actor.IP, actor.RequestID)
	}
	cert, _ := selfSignedCert(t)
	next, _ := selfSignedCert(t)

	conn, err := svc.Create(ctx, organization, CreateInput{
		Name: "IdP", IdpEntityID: "https://idp.example.com", IdpSSOURL: "https://idp.example.com/sso", IdpCertificate: cert,
	}, actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	entity := "https://idp.example.com/v2"
	if _, err := svc.Update(ctx, conn.ID, organization, UpdateInput{IdpEntityID: &entity}, actor); err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, action := range []string{"saml.connection_created", "saml.connection_updated"} {
		if n := recorded(action, conn.ID); n != 1 {
			t.Errorf("%d %s rows by the administrator, want 1", n, action)
		}
	}

	refuseAudit(t, organization, "saml.connection_updated")
	refuseAudit(t, organization, "saml.certificate_added")
	other := "https://attacker.example.com"
	if _, err := svc.Update(ctx, conn.ID, organization, UpdateInput{IdpEntityID: &other}, actor); err == nil {
		t.Error("the IdP's entity ID changed without its audit row")
	}
	if _, err := svc.AddCertificate(ctx, conn.ID, organization, next, actor); err == nil {
		t.Error("a certificate was trusted without its audit row")
	}
	got, err := svc.Get(ctx, conn.ID, organization)
	if err != nil {
		t.Fatal(err)
	}
	if got.IdpEntityID != entity || len(got.Certificates) != 1 {
		t.Errorf("connection trusts %s with %d certificates, want %s with 1: the changes stayed", got.IdpEntityID, len(got.Certificates), entity)
	}
}
