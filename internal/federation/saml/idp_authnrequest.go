package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
)

// authnRequest is the minimal subset of <AuthnRequest> we read.
type authnRequest struct {
	XMLName                     xml.Name
	ID                          string `xml:"ID,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	Issuer                      string `xml:"Issuer"`
}

// maxInflatedAuthnRequest caps a redirect-binding SAMLRequest after inflation.
const maxInflatedAuthnRequest = 256 << 10

// decodeAuthnRequest base64-decodes (and, for the redirect binding, inflates)
// a SAMLRequest. An inflated request over maxInflatedAuthnRequest is refused
// with ErrSAMLAuthnRequestInvalid.
func decodeAuthnRequest(encoded, method string) (*authnRequest, error) {
	raw, err := authnRequestXML(encoded, method)
	if err != nil {
		return nil, err
	}
	var ar authnRequest
	if err := xml.Unmarshal(raw, &ar); err != nil { // #nosec G709 -- decodes into a typed struct
		return nil, err
	}
	return &ar, nil
}

// authnRequestXML is the XML of a SAMLRequest, as decodeAuthnRequest reads it.
func authnRequestXML(encoded, method string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if method == http.MethodGet {
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		inflated, err := io.ReadAll(io.LimitReader(fr, maxInflatedAuthnRequest+1))
		if err != nil {
			return nil, err
		}
		if len(inflated) > maxInflatedAuthnRequest {
			return nil, ErrAuthnRequestInvalid
		}
		raw = inflated
	}
	return raw, nil
}

// redirectEncoded re-encodes an HTTP-POST binding SAMLRequest (base64) for the
// HTTP-Redirect binding (DEFLATE, then base64), leaving the request's XML as it
// was. A request too large for decodeAuthnRequest to inflate is refused.
func redirectEncoded(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", err
	}
	if len(raw) > maxInflatedAuthnRequest {
		return "", ErrAuthnRequestInvalid
	}
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(raw); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
