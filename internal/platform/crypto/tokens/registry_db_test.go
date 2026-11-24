//go:build integration

package tokens_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// rsaKeyPEM is one RSA private key for the whole test binary, as making one is
// slow.
var rsaKeyPEM = sync.OnceValue(func() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
})

// registry returns a signing key registry over an emptied key table.
func registry(t *testing.T) *tokens.SigningKeyRegistry {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `DELETE FROM platform.jwt_signing_keys`); err != nil {
		t.Fatal(err)
	}
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := tokens.NewSigningKeyRegistry(dbtest.Pool(t), box)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// keysByAlgorithm returns the state of the registry's key of each algorithm.
func keysByAlgorithm(t *testing.T) map[string]string {
	t.Helper()
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `SELECT algorithm, state FROM platform.jwt_signing_keys`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	states := map[string]string{}
	for rows.Next() {
		var algorithm, state string
		if err := rows.Scan(&algorithm, &state); err != nil {
			t.Fatal(err)
		}
		states[algorithm] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return states
}

// TestRegistrySignsWithAnRSAKey checks that a configured RSA key is kept as an
// RS256 key and that the issuer loaded from the registry signs with it.
func TestRegistrySignsWithAnRSAKey(t *testing.T) {
	ctx, r := dbtest.Context(t), registry(t)
	if err := r.Reconcile(ctx, rsaKeyPEM(), "", false, time.Hour); err != nil {
		t.Fatalf("keep an RSA key: %v", err)
	}
	issuer, err := r.NewIssuer(ctx, "qeet", "qeet", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("the issuer: %v", err)
	}
	if states := keysByAlgorithm(t); issuer.Alg() != "RS256" || !maps.Equal(states, map[string]string{"RS256": "active"}) {
		t.Errorf("the issuer signs %s over keys %v, want RS256 with the one active RS256 key", issuer.Alg(), states)
	}
	tok, _, err := issuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := issuer.VerifyAccess(tok); err != nil {
		t.Errorf("the issuer's own token: %v", err)
	}
}

// TestRegistryRotatesFromAnECKeyToAnRSAKey checks the two steps of a rotation
// to a key of the other type: staged, the RSA key is published and the EC key
// still signs; activated, it signs, and the EC key's tokens still verify.
func TestRegistryRotatesFromAnECKeyToAnRSAKey(t *testing.T) {
	ctx, r := dbtest.Context(t), registry(t)
	ecKeyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(ctx, ecKeyPEM, "", false, time.Hour); err != nil {
		t.Fatalf("keep the EC key: %v", err)
	}
	issuer, err := r.NewIssuer(ctx, "qeet", "qeet", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("the issuer: %v", err)
	}
	old, _, err := issuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	for _, step := range []struct {
		activate bool
		alg      string
		states   map[string]string
	}{
		{false, "ES256", map[string]string{"ES256": "active", "RS256": "candidate"}},
		{true, "RS256", map[string]string{"ES256": "retired", "RS256": "active"}},
	} {
		if err := r.Reconcile(ctx, rsaKeyPEM(), "", step.activate, time.Hour); err != nil {
			t.Fatalf("activate=%t: keep the RSA key: %v", step.activate, err)
		}
		if err := r.Sync(ctx, issuer); err != nil {
			t.Fatalf("activate=%t: reload the keys: %v", step.activate, err)
		}
		if states := keysByAlgorithm(t); issuer.Alg() != step.alg || !maps.Equal(states, step.states) {
			t.Errorf("activate=%t: the issuer signs %s over keys %v, want %s over %v", step.activate, issuer.Alg(), states, step.alg, step.states)
		}
		if n := len(issuer.JWKS()); n != 2 {
			t.Errorf("activate=%t: %d keys published, want both", step.activate, n)
		}
		if _, err := issuer.VerifyAccess(old); err != nil {
			t.Errorf("activate=%t: a token the EC key signed: %v", step.activate, err)
		}
	}
}

// TestRegistryKeepsARetiredRSAKey checks that an RSA public key listed as
// retired is kept as an RS256 key and verifies the tokens it signed.
func TestRegistryKeepsARetiredRSAKey(t *testing.T) {
	ctx, r := dbtest.Context(t), registry(t)
	retired, err := tokens.NewIssuer(rsaKeyPEM(), "qeet", "qeet", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("an issuer over the RSA key: %v", err)
	}
	old, _, err := retired.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	retiredPEM, err := tokens.PublicKeyPEM(rsaKeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	ecKeyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(ctx, ecKeyPEM, retiredPEM, false, time.Hour); err != nil {
		t.Fatalf("keep the EC key and the retired RSA key: %v", err)
	}
	issuer, err := r.NewIssuer(ctx, "qeet", "qeet", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("the issuer: %v", err)
	}
	if states := keysByAlgorithm(t); !maps.Equal(states, map[string]string{"ES256": "active", "RS256": "retired"}) {
		t.Errorf("keys %v, want the active ES256 key and the retired RS256 key", states)
	}
	if _, err := issuer.VerifyAccess(old); err != nil {
		t.Errorf("a token the retired RSA key signed: %v", err)
	}
}
