//go:build integration

package saml

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- RSA-OAEP's default digest in XML Encryption, as IdPs send it
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	xencAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	xencAES256CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
)

// spEncryptionCertificate returns the encryption certificate connID's SP
// metadata publishes.
func spEncryptionCertificate(t *testing.T, sp *spSide, connID uuid.UUID) *x509.Certificate {
	t.Helper()
	rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/metadata/"+connID.String(), nil)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rec.Body.Bytes()); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("SP metadata: %d %v %s", rec.Code, err, rec.Body.String())
	}
	data := doc.FindElement(`//KeyDescriptor[@use='encryption']/KeyInfo/X509Data/X509Certificate`)
	if data == nil {
		t.Fatalf("SP metadata publishes no encryption certificate:\n%s", rec.Body.String())
	}
	return mustParseCertificate(t, data.Text())
}

// encryptAssertion returns an edit that replaces the response's assertion with
// an EncryptedAssertion to cert: the content in method, the key in RSA-OAEP.
func encryptAssertion(t *testing.T, cert *x509.Certificate, method string) func(*etree.Element) {
	return func(response *etree.Element) {
		assertion := response.FindElement("./Assertion")
		doc := etree.NewDocument()
		doc.SetRoot(assertion.Copy())
		plain, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		switch method {
		case xencAES256GCM:
			aead, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, aead.NonceSize())
			_, _ = rand.Read(nonce)
			data = aead.Seal(nonce, nonce, plain, nil)
		case xencAES256CBC:
			pad := aes.BlockSize - len(plain)%aes.BlockSize
			padded := append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
			iv := make([]byte, aes.BlockSize)
			_, _ = rand.Read(iv)
			data = make([]byte, len(padded))
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, padded)
			data = append(iv, data...)
		}
		wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, cert.PublicKey.(*rsa.PublicKey), key, nil)
		if err != nil {
			t.Fatal(err)
		}

		encrypted := etree.NewElement("saml:EncryptedAssertion")
		ed := encrypted.CreateElement("xenc:EncryptedData")
		ed.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
		ed.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
		ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", method)
		keyInfo := ed.CreateElement("ds:KeyInfo")
		keyInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
		ek := keyInfo.CreateElement("xenc:EncryptedKey")
		ek.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
		ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
		ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(data))

		// goxmldsig leaves child indexes stale, so the assertion is swapped in
		// the child list rather than removed.
		for i, tok := range response.Child {
			if tok == assertion {
				response.Child[i] = encrypted
			}
		}
	}
}

// TestSAMLEncryptedAssertion checks that a connection's SP metadata publishes
// a certificate of its own to encrypt assertions to, whose key is stored
// sealed to the connection, and that an assertion encrypted to it signs in;
// and that one encrypted to another key, encrypted but unsigned, or sent to a
// connection that has no key, is refused.
func TestSAMLEncryptedAssertion(t *testing.T) {
	sp := newSPSide(t)
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	box, err := envelope.New(master)
	if err != nil {
		t.Fatal(err)
	}
	sp.handler.Service.SetCipher(box)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn, keyless := sp.connect(t, organization, idp), sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)

	cert := spEncryptionCertificate(t, sp, conn.ID)
	if again := spEncryptionCertificate(t, sp, conn.ID); !again.Equal(cert) {
		t.Fatal("the SP metadata published a new encryption certificate on the second fetch")
	}
	var ct, nonce []byte
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT key_ct, key_nonce FROM organization.saml_connection_keys WHERE connection_id = $1 AND organization_id = $2`,
		conn.ID, organization).Scan(&ct, &nonce); err != nil {
		t.Fatal(err)
	}
	pkcs8, err := box.Open(organization, spKeyPurpose, conn.ID.String(), ct, nonce)
	if err != nil {
		t.Fatalf("open the stored key: %v", err)
	}
	if key, err := x509.ParsePKCS8PrivateKey(pkcs8); err != nil || !key.(*rsa.PrivateKey).PublicKey.Equal(cert.PublicKey) {
		t.Fatalf("the stored key isn't the published certificate's: %v", err)
	}
	if _, err := box.Open(uuid.New(), spKeyPurpose, conn.ID.String(), ct, nonce); err == nil {
		t.Error("the stored key opened under another organisation")
	}

	sp.signIn(t, idp, conn.ID, answer{email: member.Email, edit: encryptAssertion(t, cert, xencAES256GCM)})
	sp.signIn(t, idp, conn.ID, answer{email: member.Email, edit: encryptAssertion(t, cert, xencAES256CBC)})

	_, otherPEM := selfSignedCert(t)
	other := mustParseCertificate(t, otherPEM)
	for _, c := range []struct {
		name   string
		connID uuid.UUID
		a      answer
	}{
		{"an assertion encrypted to another key", conn.ID, answer{edit: encryptAssertion(t, other, xencAES256GCM)}},
		{"an encrypted assertion that isn't signed", conn.ID, answer{unsigned: true, edit: encryptAssertion(t, cert, xencAES256GCM)}},
		{"an encrypted assertion to a connection without a key", keyless.ID, answer{edit: encryptAssertion(t, cert, xencAES256GCM)}},
	} {
		a := c.a
		a.inResponseTo, a.email = sp.begin(t, c.connID), member.Email
		if rec := sp.post(t, c.connID, idp.respond(t, c.connID, a)); rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), errs.CodeSAMLAssertionInvalid) {
			t.Errorf("%s: %d %s, want %s", c.name, rec.Code, rec.Body.String(), errs.CodeSAMLAssertionInvalid)
		}
	}
}
