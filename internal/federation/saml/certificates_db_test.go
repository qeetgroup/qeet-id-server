//go:build integration

package saml

import (
	"crypto/x509"
	"net/http"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// dropKeyInfo removes KeyInfo from every signature in the response, which the
// signature doesn't cover, so the verifier must find the certificate itself.
func dropKeyInfo(response *etree.Element) {
	for _, sig := range response.FindElements(".//Signature") {
		kept := sig.Child[:0]
		for _, tok := range sig.Child {
			if el, ok := tok.(*etree.Element); !ok || el.Tag != "KeyInfo" {
				kept = append(kept, tok)
			}
		}
		sig.Child = kept
	}
}

// TestSAMLCertificateRollover checks that a connection trusting its IdP's
// current and next certificates accepts an assertion signed with either, with
// or without KeyInfo, and only the next once the current is removed; that the
// last certificate can't be removed nor one added twice; and that another
// organisation can neither add nor remove them.
func TestSAMLCertificateRollover(t *testing.T) {
	sp := newSPSide(t)
	idp, next := newUpstreamIdP(t), newUpstreamIdP(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, tenant), tenant, tenant)
	verify(t, member.ID)
	admin, outsider := sp.asAdmin(t, tenant), sp.asAdmin(t, other)
	path := "/tenants/" + tenant.String() + "/saml/" + conn.ID.String()
	refused := func(name string, a answer, want string) {
		t.Helper()
		a.inResponseTo, a.email = sp.begin(t, conn.ID), member.Email
		if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, a)); rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %s, want %s", name, rec.Code, rec.Body.String(), want)
		}
	}

	if len(conn.Certificates) != 1 || conn.Certificates[0].NotAfter == nil || conn.Certificates[0].Source != certificateManual ||
		conn.Certificates[0].FingerprintSHA256 == "" {
		t.Fatalf("a new connection's certificates: %+v, want its one, readable", conn.Certificates)
	}
	refused("an assertion signed with the next key before it is added", answer{signer: next.signer}, errs.CodeSAMLAssertionInvalid)

	rec := dbtest.Do(t, admin, http.MethodPost, path+"/certificates", map[string]any{"certificate": next.certPEM})
	var added Certificate
	dbtest.Decode(t, rec, &added)
	if rec.Code != http.StatusCreated || added.ID == uuid.Nil || added.NotAfter == nil || added.Source != certificateManual {
		t.Fatalf("add the next certificate: %d %s", rec.Code, rec.Body.String())
	}
	for want, cert := range map[string]string{
		errs.CodeSAMLCertificateExists:  next.certPEM,
		errs.CodeSAMLCertificateInvalid: "not a certificate",
	} {
		if rec := dbtest.Do(t, admin, http.MethodPost, path+"/certificates", map[string]any{"certificate": cert}); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("add %q: %d %s, want %s", cert[:10], rec.Code, rec.Body.String(), want)
		}
	}

	sp.signIn(t, idp, conn.ID, answer{email: member.Email})
	sp.signIn(t, idp, conn.ID, answer{email: member.Email, signer: next.signer})
	sp.signIn(t, idp, conn.ID, answer{email: member.Email, signer: next.signer, edit: dropKeyInfo})
	sp.signIn(t, idp, conn.ID, answer{email: member.Email, signer: next.signer, signResponse: true, edit: dropKeyInfo})

	var got Connection
	dbtest.Decode(t, dbtest.Do(t, admin, http.MethodGet, path, nil), &got)
	if len(got.Certificates) != 2 || got.Certificates[1].ID != added.ID {
		t.Fatalf("the connection's certificates: %+v, want the current and the next", got.Certificates)
	}

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		target := "/tenants/" + other.String() + "/saml/" + conn.ID.String() + "/certificates"
		if method == http.MethodDelete {
			target += "/" + added.ID.String()
		}
		if rec := dbtest.Do(t, outsider, method, target, map[string]any{"certificate": next.certPEM}); rec.Code != http.StatusNotFound {
			t.Errorf("another organisation %s on the connection's certificates: %d %s, want 404", method, rec.Code, rec.Body.String())
		}
	}
	if rec := dbtest.Do(t, outsider, http.MethodDelete, path+"/certificates/"+added.ID.String(), nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation removing through this organisation's path: %d, want 403", rec.Code)
	}

	if rec := dbtest.Do(t, admin, http.MethodDelete, path+"/certificates/"+conn.Certificates[0].ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove the current certificate: %d %s", rec.Code, rec.Body.String())
	}
	refused("an assertion signed with the removed key", answer{}, errs.CodeSAMLAssertionInvalid)
	sp.signIn(t, idp, conn.ID, answer{email: member.Email, signer: next.signer})

	got = Connection{}
	dbtest.Decode(t, dbtest.Do(t, admin, http.MethodGet, path, nil), &got)
	if !sameCertificate(got.IdpCertificate, mustParseCertificate(t, next.certPEM)) || len(got.Certificates) != 1 {
		t.Errorf("after the rollover: idp_certificate %q, %d certificates; want only the next one", got.IdpCertificate, len(got.Certificates))
	}
	if rec := dbtest.Do(t, admin, http.MethodDelete, path+"/certificates/"+added.ID.String(), nil); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), errs.CodeSAMLCertificateLast) {
		t.Errorf("remove the last certificate: %d %s, want 409 %s", rec.Code, rec.Body.String(), errs.CodeSAMLCertificateLast)
	}
	if rec := dbtest.Do(t, admin, http.MethodDelete, path+"/certificates/"+uuid.NewString(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("remove an unknown certificate: %d, want 404", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND resource_id = $2 AND action IN ('saml.certificate_added', 'saml.certificate_removed')`, tenant, conn.ID); n != 2 {
		t.Errorf("%d certificate changes recorded, want the addition and the removal", n)
	}

	// Replacing idp_certificate makes it the only certificate trusted.
	rec = dbtest.Do(t, admin, http.MethodPatch, path, map[string]any{"idp_certificate": idp.certPEM})
	got = Connection{}
	dbtest.Decode(t, rec, &got)
	if rec.Code != http.StatusOK || len(got.Certificates) != 1 || !sameCertificate(got.Certificates[0].Certificate, mustParseCertificate(t, idp.certPEM)) {
		t.Fatalf("replace the certificate: %d %s", rec.Code, rec.Body.String())
	}
	refused("an assertion signed with a replaced key", answer{signer: next.signer}, errs.CodeSAMLAssertionInvalid)
}

// mustParseCertificate parses raw or fails the test.
func mustParseCertificate(t *testing.T, raw string) *x509.Certificate {
	t.Helper()
	cert, err := parseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
