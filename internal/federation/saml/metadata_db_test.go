//go:build integration

package saml

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// metadataServer serves an IdP's metadata, which a test can change or break.
type metadataServer struct {
	mu     sync.Mutex
	doc    string
	status int
	server *httptest.Server
}

func newMetadataServer(t *testing.T) *metadataServer {
	m := &metadataServer{status: http.StatusOK}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		w.WriteHeader(m.status)
		_, _ = w.Write([]byte(m.doc))
	}))
	t.Cleanup(m.server.Close)
	return m
}

// serve makes the server answer status with doc.
func (m *metadataServer) serve(status int, doc string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status, m.doc = status, doc
}

// der is the IdP's certificate as bare base64 DER, as metadata carries it.
func (p *upstreamIdP) der(t *testing.T) string {
	return base64.StdEncoding.EncodeToString(mustParseCertificate(t, p.certPEM).Raw)
}

// dueForRefresh makes connID's metadata look last fetched long ago.
func dueForRefresh(t *testing.T, connID uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.saml_connections SET metadata_checked_at = NOW() - INTERVAL '7 hours' WHERE id = $1`, connID); err != nil {
		t.Fatal(err)
	}
}

// TestSAMLMetadataImportAndRefresh checks that a connection created from its
// IdP's metadata URL takes the IdP's settings from it, and that the refresh job
// adds the IdP's next certificate and drops the one the metadata no longer
// lists, keeping one an administrator added; that metadata that can't be
// fetched or names another IdP changes nothing and says why; and that another
// organization can neither import into nor apply metadata to this one's.
func TestSAMLMetadataImportAndRefresh(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	sp.handler.Service.SetEgressPolicy(egress.DevelopmentPolicy())
	idp, next, manual := newUpstreamIdP(t), newUpstreamIdP(t), newUpstreamIdP(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	admin, outsider := sp.asAdmin(t, organization), sp.asAdmin(t, other)
	base := "/tenants/" + organization.String() + "/saml"
	metadata := newMetadataServer(t)
	metadata.serve(http.StatusOK, idpEntity(idp.entityID, upstreamSSO, map[string][]string{"signing": {idp.der(t)}}))

	for want, body := range map[string]map[string]any{
		errs.CodeSAMLMetadataRequired: {"name": "Okta"},
		errs.CodeSAMLMetadataInvalid:  {"name": "Okta", "metadata_xml": "<not-metadata/>"},
	} {
		if rec := dbtest.Do(t, admin, http.MethodPost, base+"/import", body); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("import %v: %d %s, want 422 %s", body, rec.Code, rec.Body.String(), want)
		}
	}
	if rec := dbtest.Do(t, outsider, http.MethodPost, base+"/import", map[string]any{"name": "Okta", "metadata_url": metadata.server.URL}); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation importing into this one: %d, want 403", rec.Code)
	}

	rec := dbtest.Do(t, admin, http.MethodPost, base+"/import", map[string]any{
		"name": "Okta", "metadata_url": metadata.server.URL, "email_attribute": "email", "status": "active",
	})
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.IdpEntityID != idp.entityID || conn.IdpSSOURL != upstreamSSO || conn.Status != "active" ||
		conn.MetadataURL == nil || *conn.MetadataURL != metadata.server.URL || conn.RefreshedAt == nil ||
		len(conn.Certificates) != 1 || conn.Certificates[0].Source != certificateMetadata {
		t.Fatalf("import from the URL: %d %s", rec.Code, rec.Body.String())
	}
	sp.signIn(t, idp, conn.ID, answer{email: member.Email})
	path := base + "/" + conn.ID.String()
	if rec := dbtest.Do(t, admin, http.MethodPost, path+"/certificates", map[string]any{"certificate": manual.certPEM}); rec.Code != http.StatusCreated {
		t.Fatalf("add a certificate by hand: %d %s", rec.Code, rec.Body.String())
	}

	// The IdP publishes its next certificate, then retires the current one.
	metadata.serve(http.StatusOK, idpEntity(idp.entityID, upstreamSSO, map[string][]string{"signing": {idp.der(t), next.der(t)}}))
	dueForRefresh(t, conn.ID)
	if run, err := RefreshMetadata(ctx, dbtest.Pool(t), egress.DevelopmentPolicy()); err != nil || run.Refreshed < 1 {
		t.Fatalf("refresh: %+v, %v", run, err)
	}
	sp.signIn(t, idp, conn.ID, answer{email: member.Email})
	sp.signIn(t, idp, conn.ID, answer{email: member.Email, signer: next.signer})
	metadata.serve(http.StatusOK, idpEntity(idp.entityID, upstreamSSO, map[string][]string{"signing": {next.der(t)}}))
	dueForRefresh(t, conn.ID)
	if _, err := RefreshMetadata(ctx, dbtest.Pool(t), egress.DevelopmentPolicy()); err != nil {
		t.Fatal(err)
	}
	var got Connection
	dbtest.Decode(t, dbtest.Do(t, admin, http.MethodGet, path, nil), &got)
	if len(got.Certificates) != 2 || !sameCertificate(got.Certificates[0].Certificate, mustParseCertificate(t, manual.certPEM)) ||
		!sameCertificate(got.Certificates[1].Certificate, mustParseCertificate(t, next.certPEM)) || got.MetadataError != nil {
		t.Fatalf("after the IdP's rollover: %+v; want the hand-added and the next certificate", got.Certificates)
	}
	a := answer{inResponseTo: sp.begin(t, conn.ID), email: member.Email}
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, a)); !strings.Contains(rec.Body.String(), errs.CodeSAMLAssertionInvalid) {
		t.Errorf("an assertion signed with the retired certificate: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLAssertionInvalid)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND resource_id = $2 AND action = 'saml.metadata_refreshed' AND actor_type = 'system'`, organization, conn.ID); n != 2 {
		t.Errorf("%d refreshes recorded, want the addition and the removal", n)
	}

	// Metadata that can't be fetched, or describes another IdP, changes nothing.
	for name, serve := range map[string]func(){
		"an error": func() { metadata.serve(http.StatusInternalServerError, "") },
		"another IdP": func() {
			metadata.serve(http.StatusOK, idpEntity("https://evil.example.test", upstreamSSO, map[string][]string{"signing": {idp.der(t)}}))
		},
	} {
		serve()
		dueForRefresh(t, conn.ID)
		if run, err := RefreshMetadata(ctx, dbtest.Pool(t), egress.DevelopmentPolicy()); err != nil || run.Failed < 1 {
			t.Fatalf("refresh with %s: %+v, %v", name, run, err)
		}
		var after Connection
		dbtest.Decode(t, dbtest.Do(t, admin, http.MethodGet, path, nil), &after)
		if after.MetadataError == nil || len(after.Certificates) != 2 || after.IdpEntityID != idp.entityID {
			t.Errorf("after metadata with %s: error %v, %d certificates, entity %s; want the reason and nothing changed",
				name, after.MetadataError, len(after.Certificates), after.IdpEntityID)
		}
	}

	if rec := dbtest.Do(t, outsider, http.MethodPost, "/tenants/"+other.String()+"/saml/"+conn.ID.String()+"/metadata", map[string]any{}); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation applying metadata to the connection: %d, want 404", rec.Code)
	}

	// Applying XML takes its settings and stops refreshing from the URL; then
	// there is nothing to refresh from.
	rec = dbtest.Do(t, admin, http.MethodPost, path+"/metadata", map[string]any{
		"metadata_xml": idpEntity(idp.entityID, upstreamSSO, map[string][]string{"signing": {idp.der(t)}}),
	})
	got = Connection{}
	dbtest.Decode(t, rec, &got)
	if rec.Code != http.StatusOK || got.MetadataURL != nil || got.MetadataError != nil || len(got.Certificates) != 2 {
		t.Fatalf("apply metadata XML: %d %s", rec.Code, rec.Body.String())
	}
	sp.signIn(t, idp, conn.ID, answer{email: member.Email})
	if rec := dbtest.Do(t, admin, http.MethodPost, path+"/metadata", map[string]any{}); !strings.Contains(rec.Body.String(), errs.CodeSAMLMetadataRequired) {
		t.Errorf("refresh a connection with no metadata URL: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLMetadataRequired)
	}
	if rec := dbtest.Do(t, admin, http.MethodPost, path+"/metadata", map[string]any{
		"metadata_xml": idpEntity("https://evil.example.test", upstreamSSO, map[string][]string{"signing": {next.der(t)}}),
	}); !strings.Contains(rec.Body.String(), errs.CodeSAMLMetadataInvalid) {
		t.Errorf("apply another IdP's metadata: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLMetadataInvalid)
	}
}

// TestSAMLMetadataImportNeedsSSOInThePlan checks that importing a connection
// from metadata, like creating one, needs a plan with SSO and fetches nothing
// without one, and that an import keeps the groups attribute it is given.
func TestSAMLMetadataImportNeedsSSOInThePlan(t *testing.T) {
	sp := newSPSide(t)
	sp.handler.Service.SetEgressPolicy(egress.DevelopmentPolicy())
	idp := newUpstreamIdP(t)
	paid, free := dbtest.Organization(t), dbtest.Organization(t)
	sp.handler.Service.SetPlanGate(poolGate{pool: dbtest.Pool(t), allowed: map[uuid.UUID]bool{paid: true}})
	metadata := newMetadataServer(t)
	metadata.serve(http.StatusOK, idpEntity(idp.entityID, upstreamSSO, map[string][]string{"signing": {idp.der(t)}}))
	body := map[string]any{"name": "Okta", "metadata_url": metadata.server.URL, "groups_attribute": "memberOf"}

	rec := dbtest.Do(t, sp.asAdmin(t, free), http.MethodPost, "/tenants/"+free.String()+"/saml/import", body)
	if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errs.CodeUpgradeRequired) {
		t.Errorf("import on a plan without SSO: %d %s, want 402 %s", rec.Code, rec.Body.String(), errs.CodeUpgradeRequired)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.saml_connections WHERE organization_id = $1`, free); n != 0 {
		t.Errorf("%d connections imported on a plan without SSO, want none", n)
	}
	rec = dbtest.Do(t, sp.asAdmin(t, paid), http.MethodPost, "/tenants/"+paid.String()+"/saml/import", body)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.GroupsAttribute != "memberOf" {
		t.Errorf("import on a plan with SSO: %d %s; want it created with its groups attribute", rec.Code, rec.Body.String())
	}
}
