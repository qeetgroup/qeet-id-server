package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testIssuer builds an ES256 issuer over a fresh key and also returns the
// private key so tests can forge tokens (missing/unknown kid, alg confusion).
func testIssuer(t *testing.T) (*Issuer, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	i, err := newIssuerFromKey(priv, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return i, priv
}

func publicPEM(t *testing.T, priv crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// rsaKey is one RSA key for the whole test binary, as making one is slow.
var rsaKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func privatePEM(t *testing.T, priv crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestIssuerConfigurationIsRestartStableAcrossInstances(t *testing.T) {
	_, privateKey := testIssuer(t)
	configured := privatePEM(t, privateKey)
	first, err := NewIssuer(configured, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("first issuer: %v", err)
	}
	second, err := NewIssuer(configured, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("second issuer: %v", err)
	}
	if first.KID() != second.KID() {
		t.Fatalf("same configured key produced different kids: %s != %s", first.KID(), second.KID())
	}
	raw, _, err := first.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
	if err != nil {
		t.Fatalf("issue on first instance: %v", err)
	}
	if _, err := second.VerifyAccess(raw); err != nil {
		t.Fatalf("second instance could not verify configured key token: %v", err)
	}
}

func TestIssuerConcurrentVerificationSnapshotAccess(t *testing.T) {
	issuer, _ := testIssuer(t)
	type retiredFixture struct {
		public string
		token  string
	}
	fixtures := make([]retiredFixture, 8)
	for index := range fixtures {
		retired, privateKey := testIssuer(t)
		raw, _, err := retired.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
		if err != nil {
			t.Fatalf("issue retired fixture: %v", err)
		}
		fixtures[index] = retiredFixture{public: publicPEM(t, privateKey), token: raw}
	}

	start := make(chan struct{})
	errorsCh := make(chan error, 32)
	var wait sync.WaitGroup
	for _, fixture := range fixtures {
		fixture := fixture
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			issuer.AddRetiredKeysPEM(fixture.public)
		}()
	}
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for range 100 {
				raw, _, err := issuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
				if err != nil {
					errorsCh <- err
					return
				}
				if _, err := issuer.VerifyAccess(raw); err != nil {
					errorsCh <- err
					return
				}
				_ = issuer.JWKS()
				_ = issuer.KeyInfo()
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatalf("concurrent issuer operation: %v", err)
	}
	for _, fixture := range fixtures {
		if _, err := issuer.VerifyAccess(fixture.token); err != nil {
			t.Fatalf("retired token did not verify after snapshot update: %v", err)
		}
	}
}

func TestNewIssuer_PEMRoundTrip(t *testing.T) {
	keyPEM, err := GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("GenerateES256KeyPEM: %v", err)
	}
	i, err := NewIssuer(keyPEM, "iss", "aud", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, _, err := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := i.VerifyAccess(tok); err != nil {
		t.Errorf("round-trip verify failed: %v", err)
	}
	// PublicKeyPEM should parse and produce an SPKI block.
	pub, err := PublicKeyPEM(keyPEM)
	if err != nil || !strings.Contains(pub, "PUBLIC KEY") {
		t.Errorf("PublicKeyPEM = %q, err = %v", pub, err)
	}
}

func TestNewIssuer_RejectsBadPEM(t *testing.T) {
	if _, err := NewIssuer("not a pem", "i", "a", time.Hour, time.Hour); err == nil {
		t.Error("NewIssuer must reject non-PEM input")
	}
}
