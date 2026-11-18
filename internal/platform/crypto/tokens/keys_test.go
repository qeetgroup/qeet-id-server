package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"maps"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLoadRetiredKeysPEMIsStrict(t *testing.T) {
	issuer, _ := testIssuer(t)
	if _, err := issuer.LoadRetiredKeysPEM("-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----"); err == nil {
		t.Fatal("malformed configured verification key must fail startup loading")
	}
	_, retiredKey := testIssuer(t)
	if count, err := issuer.LoadRetiredKeysPEM(publicPEM(t, retiredKey)); err != nil || count != 1 {
		t.Fatalf("valid configured verification key: count=%d err=%v", count, err)
	}
}

func TestKID_StableAcrossInstancesForSameKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, _ := newIssuerFromKey(priv, "i", "a", time.Hour, time.Hour)
	b, _ := newIssuerFromKey(priv, "i", "a", time.Hour, time.Hour)
	if a.KID() != b.KID() {
		t.Errorf("kid must be a deterministic thumbprint: %s vs %s", a.KID(), b.KID())
	}
}

func TestKID_ChangesWhenKeyChanges(t *testing.T) {
	a, _ := testIssuer(t)
	b, _ := testIssuer(t)
	if a.KID() == b.KID() {
		t.Error("different keys must produce different kids")
	}
}

func TestJWKS_PublishesPublicKeys(t *testing.T) {
	i, _ := testIssuer(t)
	ks := i.JWKS()
	if len(ks) != 1 {
		t.Fatalf("JWKS len = %d, want 1", len(ks))
	}
	k := ks[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Use != "sig" || k.Alg != "ES256" {
		t.Errorf("unexpected JWK shape: %+v", k)
	}
	if k.Kid != i.KID() {
		t.Errorf("JWK kid %q must match active KID %q", k.Kid, i.KID())
	}
	if k.X == "" || k.Y == "" {
		t.Error("JWK coordinates must be populated")
	}

	// A retired key shows up too, so RPs can verify in-grace tokens.
	_, oldPriv := testIssuer(t)
	i.AddRetiredKeysPEM(publicPEM(t, oldPriv))
	if len(i.JWKS()) != 2 {
		t.Errorf("JWKS should include the retired key, got %d", len(i.JWKS()))
	}
}

func TestAddRetiredKeysPEM_IgnoresGarbage(t *testing.T) {
	i, _ := testIssuer(t)
	if n := i.AddRetiredKeysPEM(""); n != 0 {
		t.Errorf("empty input registered %d keys", n)
	}
	if n := i.AddRetiredKeysPEM("-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----"); n != 0 {
		t.Errorf("garbage PEM registered %d keys", n)
	}
}

// TestRotationBetweenKeyTypes checks that after the signing key changes from
// EC to RSA or back, a token the retired key signed still verifies and both
// keys are published, each with its own algorithm.
func TestRotationBetweenKeyTypes(t *testing.T) {
	_, ecKey := testIssuer(t)
	for name, keys := range map[string][2]crypto.Signer{
		"EC to RSA": {ecKey, rsaKey()},
		"RSA to EC": {rsaKey(), ecKey},
	} {
		before, err := NewIssuer(privatePEM(t, keys[0]), "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatalf("%s: the issuer before: %v", name, err)
		}
		after, err := NewIssuer(privatePEM(t, keys[1]), "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
		if err != nil {
			t.Fatalf("%s: the issuer after: %v", name, err)
		}
		old, _, err := before.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
		if err != nil {
			t.Fatalf("%s: IssueAccess: %v", name, err)
		}
		if n, err := after.LoadRetiredKeysPEM(publicPEM(t, keys[0])); err != nil || n != 1 {
			t.Fatalf("%s: %d retired keys loaded (%v), want 1", name, n, err)
		}
		if _, err := after.VerifyAccess(old); err != nil {
			t.Errorf("%s: a token the retired key signed: %v", name, err)
		}
		fresh, _, err := after.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
		if err != nil {
			t.Fatalf("%s: IssueAccess: %v", name, err)
		}
		if _, err := after.VerifyAccess(fresh); err != nil {
			t.Errorf("%s: a token the new key signed: %v", name, err)
		}
		if decodeHeader(t, old)["alg"] == decodeHeader(t, fresh)["alg"] {
			t.Errorf("%s: both tokens are signed %v, want each key's own algorithm", name, decodeHeader(t, fresh)["alg"])
		}
		algs := map[string]string{}
		for _, k := range after.JWKS() {
			algs[k.Kty] = k.Alg
		}
		if !maps.Equal(algs, map[string]string{"EC": "ES256", "RSA": "RS256"}) {
			t.Errorf("%s: published keys by type %v, want an ES256 EC key and an RS256 RSA key", name, algs)
		}
	}
}

// TestOnlyP256AndRSA2048KeysAreAccepted checks that a key neither ES256 nor
// RS256 may sign with is refused, as the signing key and as a retired one.
func TestOnlyP256AndRSA2048KeysAreAccepted(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"RSA 1024": small, "P-384": p384, "Ed25519": ed} {
		if _, err := NewIssuer(privatePEM(t, key), "qeet-test", "qeet-test", time.Hour, 24*time.Hour); err == nil {
			t.Errorf("%s: accepted as the signing key", name)
		}
		i, _ := testIssuer(t)
		if n, err := i.LoadRetiredKeysPEM(publicPEM(t, key)); err == nil || n != 0 {
			t.Errorf("%s: %d loaded as retired keys (%v), want it refused", name, n, err)
		}
		if n := i.AddRetiredKeysPEM(publicPEM(t, key)); n != 0 {
			t.Errorf("%s: added as a retired key", name)
		}
	}
}

// PublicKeyPEM returns the SPKI ("PUBLIC KEY") PEM for a private key, the form
// JWT_RETIRED_KEYS accepts.
func PublicKeyPEM(privateKeyPEM string) (string, error) {
	priv, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
