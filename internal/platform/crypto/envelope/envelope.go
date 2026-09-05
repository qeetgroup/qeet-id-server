// Package envelope derives purpose-specific tenant keys from a deployment data
// key and binds ciphertext to its tenant, purpose, and resource using AEAD.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
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

func (c *Cipher) Open(tenantID uuid.UUID, purpose, resource string, ciphertext, nonce []byte) ([]byte, error) {
	if len(ciphertext) >= len(versionPrefix) && hmac.Equal(ciphertext[:len(versionPrefix)], versionPrefix) {
		aead, aad, err := c.contextAEAD(tenantID, purpose, resource)
		if err != nil {
			return nil, err
		}
		return aead.Open(nil, nonce, ciphertext[len(versionPrefix):], aad)
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
	derived := hkdfSHA256(c.master, []byte("qeet-id-envelope-v1"), aad)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, aad, err
}

func hkdfSHA256(ikm, salt, info []byte) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{1})
	return expand.Sum(nil)
}
