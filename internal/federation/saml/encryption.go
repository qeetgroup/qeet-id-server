package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

const (
	spKeyPurpose  = "saml-sp-key"             // envelope purpose a connection's SP key is sealed under
	spKeyBits     = 2048                      // RSA key size IdPs encrypt to
	spKeyLifetime = 10 * 365 * 24 * time.Hour // certificate validity; IdPs pin it rather than chain it
)

// spEncryptionKeyDescriptor publishes, in a connection's SP metadata, the
// certificate its IdP encrypts assertions to and the algorithms the ACS
// decrypts, authenticated ones first.
const spEncryptionKeyDescriptor = `
    <KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    </KeyDescriptor>`

// SetCipher sets the envelope cipher the connections' SP keys are sealed with.
// Without one no key is made, and an encrypted assertion is refused.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// encryptionCertificate returns, base64 DER, the certificate conn's IdP
// encrypts assertions to, making the connection's key pair the first time it
// is asked for; "" without a cipher.
func (s *Service) encryptionCertificate(ctx context.Context, conn *Connection) (string, error) {
	if s.box == nil {
		return "", nil
	}
	key := dbgen.GetSamlConnectionKeyParams{ConnectionID: conn.ID, TenantID: conn.TenantID}
	row, err := s.q.GetSamlConnectionKey(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := s.createEncryptionKey(ctx, conn); err != nil {
			return "", err
		}
		row, err = s.q.GetSamlConnectionKey(ctx, key)
	}
	if err != nil {
		return "", err
	}
	cert, err := parseCertificate(row.Certificate)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cert.Raw), nil
}

// createEncryptionKey makes conn's SP key pair and stores it, the private key
// sealed to the organisation and connection. A concurrent first request may
// make one too; the first stored wins.
func (s *Service) createEncryptionKey(ctx context.Context, conn *Connection) error {
	key, err := rsa.GenerateKey(rand.Reader, spKeyBits)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Qeet ID SAML SP " + conn.ID.String()},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(spKeyLifetime),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(pkcs8)
	ct, nonce, err := s.box.Seal(conn.TenantID, spKeyPurpose, conn.ID.String(), pkcs8)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return s.q.InsertSamlConnectionKey(ctx, dbgen.InsertSamlConnectionKeyParams{
		ConnectionID: conn.ID, TenantID: conn.TenantID, Certificate: certificatePEM(cert), KeyCt: ct, KeyNonce: nonce,
	})
}

// decryptionKey returns conn's SP key pair for decrypting its IdP's
// assertions, or nil when it has none.
func (s *Service) decryptionKey(ctx context.Context, conn *Connection) (*tls.Certificate, error) {
	if s.box == nil {
		return nil, nil
	}
	row, err := s.q.GetSamlConnectionKey(ctx, dbgen.GetSamlConnectionKeyParams{ConnectionID: conn.ID, TenantID: conn.TenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pkcs8, err := s.box.Open(conn.TenantID, spKeyPurpose, conn.ID.String(), row.KeyCt, row.KeyNonce)
	if err != nil {
		return nil, fmt.Errorf("open the SP key: %w", err)
	}
	defer clear(pkcs8)
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("parse the SP key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the SP key is not RSA")
	}
	cert, err := parseCertificate(row.Certificate)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}, nil
}
