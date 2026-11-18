package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestDecodeAuthnRequestRedirectBinding round-trips an AuthnRequest through the
// HTTP-Redirect binding (raw-DEFLATE + base64) and the HTTP-POST binding.
func TestDecodeAuthnRequestRedirectBinding(t *testing.T) {
	raw := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
		`ID="_abc123" AssertionConsumerServiceURL="https://sp.example.com/acs">` +
		`<saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>`

	// Redirect binding: raw DEFLATE then base64.
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte(raw))
	_ = fw.Close()
	redirect := base64.StdEncoding.EncodeToString(buf.Bytes())

	ar, err := decodeAuthnRequest(redirect, http.MethodGet)
	if err != nil {
		t.Fatalf("decode (redirect): %v", err)
	}
	if ar.ID != "_abc123" || ar.Issuer != "https://sp.example.com/metadata" ||
		ar.AssertionConsumerServiceURL != "https://sp.example.com/acs" {
		t.Errorf("redirect parse mismatch: %+v", ar)
	}

	// POST binding: plain base64 (no DEFLATE).
	post := base64.StdEncoding.EncodeToString([]byte(raw))
	ar2, err := decodeAuthnRequest(post, http.MethodPost)
	if err != nil {
		t.Fatalf("decode (post): %v", err)
	}
	if ar2.Issuer != "https://sp.example.com/metadata" {
		t.Errorf("post parse Issuer = %q", ar2.Issuer)
	}
}

// TestDecodeAuthnRequestInflatedSizeLimit checks that a redirect-binding
// request decodes up to maxInflatedAuthnRequest and is refused above it.
func TestDecodeAuthnRequestInflatedSizeLimit(t *testing.T) {
	request := func(size int) string {
		head := `<AuthnRequest ID="_sized"><Issuer>https://sp.example.com</Issuer><Extensions>`
		tail := `</Extensions></AuthnRequest>`
		return head + strings.Repeat("a", size-len(head)-len(tail)) + tail
	}
	for _, c := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"at the limit", maxInflatedAuthnRequest, false},
		{"one byte over", maxInflatedAuthnRequest + 1, true},
		{"far over", 8 << 20, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(fuzzDeflate(request(c.size)))
			ar, err := decodeAuthnRequest(encoded, http.MethodGet)
			if c.wantErr {
				if !errors.Is(err, ErrAuthnRequestInvalid) {
					t.Fatalf("decodeAuthnRequest = (%v, %v), want ErrSAMLAuthnRequestInvalid", ar, err)
				}
				return
			}
			if err != nil || ar.ID != "_sized" {
				t.Fatalf("decodeAuthnRequest = (%+v, %v), want ID _sized", ar, err)
			}
		})
	}
}

// maxFuzzSAMLRequest caps the encoded SAMLRequest the fuzz target decodes.
const maxFuzzSAMLRequest = 4 << 10

func fuzzDeflate(raw string) []byte {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte(raw))
	_ = fw.Close()
	return buf.Bytes()
}

// FuzzDecodeAuthnRequest checks that decodeAuthnRequest never panics on either
// binding and returns exactly one of a request or an error.
func FuzzDecodeAuthnRequest(f *testing.F) {
	requests := []string{
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
			`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
			`ID="_abc123" AssertionConsumerServiceURL="https://sp.example.com/acs">` +
			`<saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>`,
		`<AuthnRequest ID="x"/>`,
		`<AuthnRequest><Issuer></Issuer><Issuer>second</Issuer></AuthnRequest>`,
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><AuthnRequest ID="&a;"/>`,
		`<AuthnRequest ID="a" ID="b"/>`,
		`<AuthnRequest><Issuer><![CDATA[https://sp.example.com]]></Issuer>`,
		`<a:AuthnRequest xmlns:a="urn:x" a:ID="1"><a:Issuer>i</a:Issuer></a:AuthnRequest>`,
		"<AuthnRequest ID=\"\xff\xfe\"/>",
		`not xml at all`,
		``,
	}
	for _, raw := range requests {
		f.Add(base64.StdEncoding.EncodeToString([]byte(raw)), false)
		f.Add(base64.StdEncoding.EncodeToString(fuzzDeflate(raw)), true)
	}
	f.Add("  "+base64.StdEncoding.EncodeToString([]byte(requests[0]))+"\r\n", false)
	f.Add(base64.URLEncoding.EncodeToString(fuzzDeflate(requests[0])), true)
	f.Add(base64.RawStdEncoding.EncodeToString([]byte(requests[1])), false)
	f.Add(base64.StdEncoding.EncodeToString([]byte(requests[1])), true) // not deflated
	f.Add(base64.StdEncoding.EncodeToString(fuzzDeflate(requests[0])[:8]), true)
	f.Add("%%%not-base64%%%", false)
	f.Add("", true)

	f.Fuzz(func(t *testing.T, encoded string, redirect bool) {
		if len(encoded) > maxFuzzSAMLRequest {
			t.Skip()
		}
		method := http.MethodPost
		if redirect {
			method = http.MethodGet
		}
		ar, err := decodeAuthnRequest(encoded, method)
		if (ar == nil) == (err == nil) {
			t.Fatalf("decodeAuthnRequest = (%v, %v), want exactly one of request or error", ar, err)
		}
	})
}
