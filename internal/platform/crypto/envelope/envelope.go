// Package envelope derives purpose-specific tenant keys from a deployment data
// key and binds ciphertext to its tenant, purpose, and resource using AEAD.
// Each ciphertext names the data key that sealed it, so the key can be rotated:
// a Cipher seals with its current key and opens what any of its keys sealed.
package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// A ciphertext is a version prefix, then (from version 2) the id of the data
// key that sealed it, then the AES-GCM output; its nonce is stored beside it.
// Ciphertext without a prefix is the oldest scheme: AES-GCM under the data key.
var (
	prefixV1 = []byte{'Q', 'E', 'V', 1} // bound to its context; names no key
	prefixV2 = []byte{'Q', 'E', 'V', 2} // bound to its context; followed by the key id
)

// KeyIDSize is the length of the key id a ciphertext carries.
const KeyIDSize = 8

// ErrUnknownKey means a ciphertext names a data key the Cipher doesn't hold,
// such as a previous key removed while values it sealed remain.
var ErrUnknownKey = errors.New("envelope: sealed with a data key that is not configured")

// errNonceSize refuses opening with a stored nonce of the wrong length, which
// the AEAD would otherwise panic on.
var errNonceSize = errors.New("envelope: nonce has the wrong length")

var errTruncated = errors.New("envelope: ciphertext is too short to name its key")

// dataKey is one data key and its id.
type dataKey struct {
	id     [KeyIDSize]byte
	master []byte
	legacy cipher.AEAD // the data key used directly, for the oldest scheme
}

// Cipher encrypts with keys derived from its current data key per tenant,
// purpose and resource, and decrypts what any of its data keys sealed.
type Cipher struct {
	keys   []*dataKey // the current key first
	prefix []byte     // what the current key's ciphertext starts with
}

// New returns a Cipher that seals with current and opens what current or any
// of previous sealed. Each is a 16, 24 or 32 byte data key.
func New(current []byte, previous ...[]byte) (*Cipher, error) {
	c := &Cipher{}
	for _, master := range append([][]byte{current}, previous...) {
		k, err := newDataKey(master)
		if err != nil {
			return nil, err
		}
		if same := c.key(k.id[:]); same != nil {
			if !hmac.Equal(same.master, k.master) {
				return nil, errors.New("envelope: two data keys have the same id")
			}
			continue
		}
		c.keys = append(c.keys, k)
	}
	c.prefix = append(append([]byte(nil), prefixV2...), c.keys[0].id[:]...)
	return c, nil
}

func newDataKey(master []byte) (*dataKey, error) {
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
	// The id is a one-way fingerprint of the key, so any Cipher given the same
	// key names it the same way and the id reveals nothing of the key.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("qeet-id-envelope-key-id"))
	k := &dataKey{master: key, legacy: legacy}
	copy(k.id[:], mac.Sum(nil))
	return k, nil
}

// key returns the data key with id, or nil.
func (c *Cipher) key(id []byte) *dataKey {
	for _, k := range c.keys {
		if bytes.Equal(k.id[:], id) {
			return k
		}
	}
	return nil
}

// KeyIDs returns the hex ids of the Cipher's data keys, the current one first.
func (c *Cipher) KeyIDs() []string {
	ids := make([]string, len(c.keys))
	for i, k := range c.keys {
		ids[i] = hex.EncodeToString(k.id[:])
	}
	return ids
}

// CurrentPrefix returns the bytes every ciphertext the current key seals
// starts with, so stored values sealed otherwise can be found.
func (c *Cipher) CurrentPrefix() []byte { return append([]byte(nil), c.prefix...) }

// Seal encrypts plaintext under the current key for tenantID, purpose and
// resource, and returns the ciphertext and its nonce.
func (c *Cipher) Seal(tenantID uuid.UUID, purpose, resource string, plaintext []byte) ([]byte, []byte, error) {
	aead, aad, err := c.keys[0].contextAEAD(2, tenantID, purpose, resource)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := make([]byte, 0, len(c.prefix)+len(plaintext)+aead.Overhead())
	ciphertext = append(ciphertext, c.prefix...)
	return aead.Seal(ciphertext, nonce, plaintext, aad), nonce, nil
}

// Open decrypts what Seal returned for the same tenantID, purpose and
// resource under any of the Cipher's keys, or a ciphertext of an older scheme.
// A ciphertext naming a key the Cipher doesn't hold fails with ErrUnknownKey.
func (c *Cipher) Open(tenantID uuid.UUID, purpose, resource string, ciphertext, nonce []byte) ([]byte, error) {
	switch {
	case bytes.HasPrefix(ciphertext, prefixV2):
		rest := ciphertext[len(prefixV2):]
		if len(rest) < KeyIDSize {
			return nil, errTruncated
		}
		k := c.key(rest[:KeyIDSize])
		if k == nil {
			return nil, fmt.Errorf("%w (key id %x)", ErrUnknownKey, rest[:KeyIDSize])
		}
		return k.open(2, tenantID, purpose, resource, rest[KeyIDSize:], nonce)
	case bytes.HasPrefix(ciphertext, prefixV1):
		return c.openAny(func(k *dataKey) ([]byte, error) {
			return k.open(1, tenantID, purpose, resource, ciphertext[len(prefixV1):], nonce)
		})
	default:
		return c.openAny(func(k *dataKey) ([]byte, error) {
			if len(nonce) != k.legacy.NonceSize() {
				return nil, errNonceSize
			}
			return k.legacy.Open(nil, nonce, ciphertext, nil)
		})
	}
}

// openAny opens a ciphertext that names no key with each key in turn, the
// current one first: authentication fails under any key but the one that
// sealed it.
func (c *Cipher) openAny(open func(*dataKey) ([]byte, error)) ([]byte, error) {
	var first error
	for _, k := range c.keys {
		plaintext, err := open(k)
		if err == nil {
			return plaintext, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

// IsCurrent reports whether ciphertext was sealed with the current key and
// scheme, so any other can be re-sealed.
func (c *Cipher) IsCurrent(ciphertext []byte) bool { return bytes.HasPrefix(ciphertext, c.prefix) }

func (k *dataKey) open(version int, tenantID uuid.UUID, purpose, resource string, sealed, nonce []byte) ([]byte, error) {
	aead, aad, err := k.contextAEAD(version, tenantID, purpose, resource)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errNonceSize
	}
	return aead.Open(nil, nonce, sealed, aad)
}

func (k *dataKey) contextAEAD(version int, tenantID uuid.UUID, purpose, resource string) (cipher.AEAD, []byte, error) {
	if tenantID == uuid.Nil || purpose == "" || resource == "" {
		return nil, nil, errors.New("tenant, purpose, and resource encryption context are required")
	}
	var keyID string
	if version >= 2 {
		keyID = hex.EncodeToString(k.id[:])
	}
	aad, err := json.Marshal(struct {
		Version  int       `json:"version"`
		Key      string    `json:"key,omitempty"`
		Tenant   uuid.UUID `json:"tenant"`
		Purpose  string    `json:"purpose"`
		Resource string    `json:"resource"`
	}{Version: version, Key: keyID, Tenant: tenantID, Purpose: purpose, Resource: resource})
	if err != nil {
		return nil, nil, err
	}
	// Salt is the fixed scheme label and info is the encryption context, so
	// every (tenant, purpose, resource) gets its own key from the one DEK.
	salt := fmt.Sprintf("qeet-id-envelope-v%d", version)
	derived, err := hkdf.Key(sha256.New, k.master, []byte(salt), string(aad), 32)
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
