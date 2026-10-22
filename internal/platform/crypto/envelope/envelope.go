// Package envelope derives purpose-specific tenant keys from a deployment data
// key and binds ciphertext to its tenant, purpose, and resource using AEAD.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

var versionPrefix = []byte{'Q', 'E', 'V', 1}

type Cipher struct {
	master []byte
	legacy cipher.AEAD
}

func New(master []byte) (*Cipher, error) {
	switch len(master) {
	case 16, 24, 32:
	default:
		return nil, errors.New("envelope key must contain 16, 24, or 32 bytes")
	}
	key := append([]byte(nil), master...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	legacy, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{master: key, legacy: legacy}, nil
}

func (c *Cipher) Seal(tenantID uuid.UUID, purpose, resource string, plaintext []byte) ([]byte, []byte, error) {
	aead, aad, err := c.contextAEAD(tenantID, purpose, resource)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	ciphertext := make([]byte, 0, len(versionPrefix)+len(sealed))
	ciphertext = append(ciphertext, versionPrefix...)
	ciphertext = append(ciphertext, sealed...)
	return ciphertext, nonce, nil
}

// errNonceSize refuses opening with a stored nonce of the wrong length, which
// the AEAD would otherwise panic on.
var errNonceSize = errors.New("envelope: nonce has the wrong length")

func (c *Cipher) Open(tenantID uuid.UUID, purpose, resource string, ciphertext, nonce []byte) ([]byte, error) {
	if len(ciphertext) >= len(versionPrefix) && hmac.Equal(ciphertext[:len(versionPrefix)], versionPrefix) {
		aead, aad, err := c.contextAEAD(tenantID, purpose, resource)
		if err != nil {
			return nil, err
		}
		if len(nonce) != aead.NonceSize() {
			return nil, errNonceSize
		}
		return aead.Open(nil, nonce, ciphertext[len(versionPrefix):], aad)
	}
	if len(nonce) != c.legacy.NonceSize() {
		return nil, errNonceSize
	}
	return c.legacy.Open(nil, nonce, ciphertext, nil)
}

func (c *Cipher) IsCurrent(ciphertext []byte) bool {
	return len(ciphertext) >= len(versionPrefix) && hmac.Equal(ciphertext[:len(versionPrefix)], versionPrefix)
}

func (c *Cipher) contextAEAD(tenantID uuid.UUID, purpose, resource string) (cipher.AEAD, []byte, error) {
	if tenantID == uuid.Nil || purpose == "" || resource == "" {
		return nil, nil, errors.New("tenant, purpose, and resource encryption context are required")
	}
	aad, err := json.Marshal(struct {
		Version  int       `json:"version"`
		Tenant   uuid.UUID `json:"tenant"`
		Purpose  string    `json:"purpose"`
		Resource string    `json:"resource"`
	}{Version: 1, Tenant: tenantID, Purpose: purpose, Resource: resource})
	if err != nil {
		return nil, nil, err
	}
	// Salt is the fixed scheme label and info is the encryption context, so
	// every (tenant, purpose, resource) gets its own key from the one DEK.
	derived, err := hkdf.Key(sha256.New, c.master, []byte("qeet-id-envelope-v1"), string(aad), 32)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, aad, err
}
