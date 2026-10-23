package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/http"
	"testing"
)

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
