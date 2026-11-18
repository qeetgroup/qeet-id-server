package saml

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// idpEntity is an IdP's EntityDescriptor with an HTTP-Redirect and an
// HTTP-POST SSO endpoint, and a KeyDescriptor of each use for every
// certificate in keys, keyed by use ("" for none).
func idpEntity(entityID, sso string, keys map[string][]string) string {
	var b strings.Builder
	b.WriteString(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + entityID + `">`)
	b.WriteString(`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
	for use, certs := range keys {
		for _, cert := range certs {
			attr := ""
			if use != "" {
				attr = ` use="` + use + `"`
			}
			b.WriteString(`<md:KeyDescriptor` + attr + `><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + cert +
				`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
		}
	}
	b.WriteString(`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://post.example.test/sso"/>`)
	b.WriteString(`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + sso + `"/>`)
	b.WriteString(`</md:IDPSSODescriptor></md:EntityDescriptor>`)
	return b.String()
}

// TestParseIdPMetadata checks that an IdP's entity ID, redirect SSO endpoint
// and signing certificates are read from its metadata, alone or among others,
// and that metadata a connection can't use is refused, saying why.
func TestParseIdPMetadata(t *testing.T) {
	_, current := selfSignedCert(t)
	_, next := selfSignedCert(t)
	_, encryption := selfSignedCert(t)
	okta := idpEntity("https://okta.example.test", "https://okta.example.test/sso", map[string][]string{
		"signing": {current}, "": {next}, "encryption": {encryption},
	})

	md, err := parseIdPMetadata([]byte(okta), "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if md.EntityID != "https://okta.example.test" || md.SSOURL != "https://okta.example.test/sso" || len(md.Certificates) != 2 {
		t.Fatalf("read %s %s and %d certificates; want the entity, its redirect endpoint and the two signing certificates",
			md.EntityID, md.SSOURL, len(md.Certificates))
	}
	for _, cert := range md.Certificates {
		if sameCertificate(encryption, cert) {
			t.Error("the encryption certificate was read as a signing one")
		}
	}

	entra := idpEntity("https://entra.example.test", "https://entra.example.test/sso", map[string][]string{"signing": {next}})
	both := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + okta + entra + `</EntitiesDescriptor>`
	if md, err := parseIdPMetadata([]byte(both), "https://entra.example.test"); err != nil || md.EntityID != "https://entra.example.test" || len(md.Certificates) != 1 {
		t.Errorf("pick one of two IdPs: %+v, %v", md, err)
	}

	sp := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`
	for name, c := range map[string]struct{ doc, entityID string }{
		"two IdPs, neither named":   {both, ""},
		"an IdP it doesn't contain": {okta, "https://other.example.test"},
		"a service provider":        {sp, ""},
		"not XML":                   {"not metadata", ""},
		"another document":          {`<html xmlns="http://www.w3.org/1999/xhtml"/>`, ""},
		"no signing certificate":    {idpEntity("https://idp.example.test", "https://idp.example.test/sso", map[string][]string{"encryption": {encryption}}), ""},
		"a broken certificate":      {idpEntity("https://idp.example.test", "https://idp.example.test/sso", map[string][]string{"signing": {"bm90IGEgY2VydA=="}}), ""},
		"a plain http SSO endpoint": {idpEntity("https://idp.example.test", "http://idp.example.test/sso", map[string][]string{"signing": {current}}), ""},
		"too large":                 {strings.Repeat(" ", maxMetadataBytes+1), ""},
	} {
		if _, err := parseIdPMetadata([]byte(c.doc), c.entityID); !errors.Is(err, ErrMetadataInvalid) || errs.As(err).Detail == "" {
			t.Errorf("%s: %v, want %s saying why", name, err, CodeMetadataInvalid)
		}
	}
}

// TestFetchMetadata checks that metadata is fetched within the egress policy:
// a private address is refused unless the policy allows it, and an answer that
// isn't 200, or is too large, is refused.
func TestFetchMetadata(t *testing.T) {
	_, cert := selfSignedCert(t)
	doc := idpEntity("https://idp.example.test", "https://idp.example.test/sso", map[string][]string{"signing": {cert}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata":
			_, _ = w.Write([]byte(doc))
		case "/large":
			_, _ = w.Write([]byte(strings.Repeat(" ", maxMetadataBytes+1)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	ctx := context.Background()

	public := newTestService(t, new(pgxpool.Pool), new(auth.Service))
	for _, raw := range []string{server.URL + "/metadata", "https://127.0.0.1/metadata", "https://user:pass@idp.example.test/m", "ftp://idp.example.test/m"} {
		if _, err := public.fetchMetadata(ctx, raw); !errors.Is(err, ErrMetadataURLInvalid) {
			t.Errorf("fetch %s under the public policy: %v, want %s", raw, err, CodeMetadataURLInvalid)
		}
	}

	local := newTestService(t, new(pgxpool.Pool), new(auth.Service), func(d *Deps) { d.Egress = egress.DevelopmentPolicy() })
	md, err := local.LoadMetadata(ctx, server.URL+"/metadata", "", "")
	if err != nil || md.EntityID != "https://idp.example.test" {
		t.Fatalf("load from the URL: %+v, %v", md, err)
	}
	if _, err := local.fetchMetadata(ctx, server.URL+"/missing"); !errors.Is(err, ErrMetadataUnreachable) {
		t.Errorf("a 404: %v, want %s", err, CodeMetadataUnreachable)
	}
	if _, err := local.fetchMetadata(ctx, server.URL+"/large"); !errors.Is(err, ErrMetadataInvalid) {
		t.Errorf("an oversized document: %v, want %s", err, CodeMetadataInvalid)
	}
	for name, c := range map[string][2]string{"neither": {"", ""}, "both": {server.URL + "/metadata", doc}} {
		if _, err := local.LoadMetadata(ctx, c[0], c[1], ""); !errors.Is(err, ErrMetadataRequired) {
			t.Errorf("load with %s a URL and XML: %v, want %s", name, err, CodeMetadataRequired)
		}
	}
}
