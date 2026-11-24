package saml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- rsa-oaep-mgf1p, the key transport every SP decrypts, is defined over SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// An app's certificate is kept for what it is used for: verifying the
// sign-in requests the app signs, encrypting the assertions sent to it, or
// both.

const (
	nsXMLEnc     = "http://www.w3.org/2001/04/xmlenc#"
	algAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	algRSAOAEP   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	algSHA1      = "http://www.w3.org/2000/09/xmldsig#sha1"
)

// CertificateDetails is what an app's certificate says about itself.
type CertificateDetails struct {
	Subject           string    `json:"subject"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
}

// certificateDetails reads pemText's details, or nil when there is none or it
// doesn't parse.
func certificateDetails(pemText string) *CertificateDetails {
	if strings.TrimSpace(pemText) == "" {
		return nil
	}
	cert, err := parseCertificate(pemText)
	if err != nil {
		return nil
	}
	return &CertificateDetails{
		Subject: cert.Subject.String(), FingerprintSHA256: fingerprint(cert),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
	}
}

// checkCertificateUse refuses a certificate kept for nothing, a use without a
// certificate, and encryption to a key that isn't RSA.
func checkCertificateUse(certPEM string, requireSigned, encrypt bool) error {
	has := strings.TrimSpace(certPEM) != ""
	switch {
	case has && !requireSigned && !encrypt:
		return ErrCertificateUnused
	case !has && (requireSigned || encrypt):
		return ErrCertificateRequired
	case !has:
		return nil
	}
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return ErrCertificateInvalid
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); encrypt && !ok {
		return ErrEncryptionKeyUnsupported
	}
	return nil
}

// verifiedAuthnRequest checks that sign-in request raw, as r carried it, is signed with certPEM, and
// returns it as signed. A Redirect-binding request is signed over its query and the SAMLRequest read is
// the one signed; a posted one (or one carried back from the hosted login) by an enveloped XML
// signature, and only the element it covers is read.
func verifiedAuthnRequest(r *http.Request, raw []byte, certPEM string) (*authnRequest, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, ErrRequestSignatureInvalid
	}
	if r.Method == http.MethodGet && r.URL.Query().Get("Signature") != "" {
		samlRequest, err := verifyRedirectSignature(r.URL.RawQuery, cert)
		if err != nil {
			return nil, ErrRequestSignatureInvalid
		}
		signed, err := authnRequestXML(samlRequest, http.MethodGet)
		if err != nil {
			return nil, ErrAuthnRequestInvalid
		}
		var ar authnRequest
		if err := xml.Unmarshal(signed, &ar); err != nil { // #nosec G709 -- decodes into a typed struct
			return nil, ErrAuthnRequestInvalid
		}
		return &ar, nil
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, ErrAuthnRequestInvalid
	}
	vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	vctx.IdAttribute = "ID"
	signed, err := vctx.Validate(doc.Root())
	if err != nil {
		return nil, ErrRequestSignatureInvalid
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	b, err := out.WriteToBytes()
	if err != nil {
		return nil, err
	}
	var ar authnRequest
	if err := xml.Unmarshal(b, &ar); err != nil { // #nosec G709 -- decodes into a typed struct
		return nil, ErrAuthnRequestInvalid
	}
	return &ar, nil
}

// verifyRedirectSignature checks a Redirect-binding query's Signature over SAMLRequest, RelayState when
// present, and SigAlg, as their URL-encoded values arrived (SAML bindings §3.4.4.1), and returns the
// signed SAMLRequest. Any of the four given twice, or under a percent-encoded name, is refused, so a
// form parser reads the signed values. SHA-1 is refused.
func verifyRedirectSignature(rawQuery string, cert *x509.Certificate) (string, error) {
	values := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(k)
		if err != nil {
			return "", ErrRequestSignatureInvalid
		}
		switch name {
		case "SAMLRequest", "RelayState", "SigAlg", "Signature":
			if _, seen := values[name]; seen || name != k {
				return "", ErrRequestSignatureInvalid
			}
			values[name] = v
		}
	}
	samlRequest, ok := values["SAMLRequest"]
	if !ok {
		return "", ErrRequestSignatureInvalid
	}
	signed := "SAMLRequest=" + samlRequest
	if relay, ok := values["RelayState"]; ok {
		signed += "&RelayState=" + relay
	}
	signed += "&SigAlg=" + values["SigAlg"]
	request, err := url.QueryUnescape(samlRequest)
	if err != nil {
		return "", err
	}
	alg, err := url.QueryUnescape(values["SigAlg"])
	if err != nil {
		return "", err
	}
	sigText, err := url.QueryUnescape(values["Signature"])
	if err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil {
		return "", err
	}
	var hash crypto.Hash
	var sum []byte
	switch alg {
	case dsig.RSASHA256SignatureMethod, dsig.ECDSASHA256SignatureMethod:
		d := sha256.Sum256([]byte(signed))
		hash, sum = crypto.SHA256, d[:]
	case dsig.RSASHA512SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		d := sha512.Sum512([]byte(signed))
		hash, sum = crypto.SHA512, d[:]
	default:
		return "", ErrRequestSignatureInvalid
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, hash, sum, sig); err != nil {
			return "", err
		}
		return request, nil
	case *ecdsa.PublicKey:
		// XML signatures carry ECDSA as r and s side by side (XML-DSig 1.1 §6.4.3).
		half := len(sig) / 2
		if len(sig) == 0 || len(sig)%2 != 0 ||
			!ecdsa.Verify(pub, sum, new(big.Int).SetBytes(sig[:half]), new(big.Int).SetBytes(sig[half:])) {
			return "", ErrRequestSignatureInvalid
		}
		return request, nil
	}
	return "", ErrRequestSignatureInvalid
}

// sealAssertion encrypts the signed assertion to cert's RSA key as an
// EncryptedAssertion: AES-256-GCM under a fresh key, carried by RSA-OAEP.
func sealAssertion(assertion *etree.Element, cert *x509.Certificate) (*etree.Element, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrEncryptionKeyUnsupported
	}
	doc := etree.NewDocument()
	doc.SetRoot(assertion.Copy())
	plain, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(bytes.Clone(nonce), nonce, plain, nil)
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil) // #nosec G401 -- rsa-oaep-mgf1p is defined over SHA-1
	if err != nil {
		return nil, err
	}

	encrypted := etree.NewElement("saml:EncryptedAssertion")
	data := encrypted.CreateElement("xenc:EncryptedData")
	data.CreateAttr("xmlns:xenc", nsXMLEnc)
	data.CreateAttr("Type", nsXMLEnc+"Element")
	data.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", algAES256GCM)
	keyInfo := data.CreateElement("ds:KeyInfo")
	keyInfo.CreateAttr("xmlns:ds", dsig.Namespace)
	encKey := keyInfo.CreateElement("xenc:EncryptedKey")
	method := encKey.CreateElement("xenc:EncryptionMethod")
	method.CreateAttr("Algorithm", algRSAOAEP)
	method.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", algSHA1)
	encKey.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
	data.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(sealed))
	return encrypted, nil
}

// idpCertificate serves the certificate the organization's IdP signs
// assertions with, as PEM, for an SP that asks for the certificate on its own.
func (h *Handler) idpCertificate(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		httpx.WriteError(w, r, ErrIdPNotConfigured)
		return
	}
	if _, err := h.idpOrganization(r); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="qeet-idp-signing.pem"`)
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: h.IdP.signer.certDER})
}
