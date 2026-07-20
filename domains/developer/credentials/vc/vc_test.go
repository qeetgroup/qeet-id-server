package vc

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/platform/api/rest/errs"
	tokens "github.com/qeetgroup/qeet-id-server/platform/security/tokens"
)

// Issue's input validation runs before any DB/issuer use, and Verify rejects
// unverifiable tokens before touching the DB — both unit-testable. The
// issue→store→verify round-trip (needs DB + revocation registry) is integration.

func newTestIssuer(t *testing.T) *tokens.Issuer {
	t.Helper()
	key, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("GenerateES256KeyPEM: %v", err)
	}
	iss, err := tokens.NewIssuer(key, "https://issuer.test", "test-aud", 15*time.Minute, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func TestIssue_RequiresSubjectAndType(t *testing.T) {
	// nil pool/issuer is safe: validation returns before either is used.
	s := &Service{}

	cases := []struct{ subject, credType string }{
		{"", "EmployeeBadge"},
		{"did:example:123", ""},
		{"   ", "EmployeeBadge"}, // whitespace-only subject
		{"did:example:123", "  "},
	}
	for _, c := range cases {
		res, err := s.Issue(context.Background(), [16]byte{}, c.subject, c.credType, nil, 0)
		if res != nil {
			t.Errorf("subject=%q type=%q: expected nil result", c.subject, c.credType)
		}
		e := errs.As(err)
		if e == nil || e.Status != 422 {
			t.Errorf("subject=%q type=%q: want 422 unprocessable, got %v", c.subject, c.credType, err)
		}
	}
}

func TestVerify_RejectsUnparseableTokens(t *testing.T) {
	s := &Service{issuer: newTestIssuer(t)} // nil pool: VerifyVC fails before DB

	for _, raw := range []string{"", "not-a-jwt", "a.b.c", "header.payload"} {
		res, err := s.Verify(context.Background(), raw)
		if err != nil {
			t.Errorf("raw=%q: unexpected error %v (Verify should return a result, not error)", raw, err)
		}
		if res == nil || res.Valid {
			t.Errorf("raw=%q: expected Valid=false, got %+v", raw, res)
		}
	}
}

func TestVerify_RejectsTokenSignedByDifferentKey(t *testing.T) {
	signer := newTestIssuer(t)   // key A — mints the token
	verifier := newTestIssuer(t) // key B — different key, must reject

	tokenA, err := signer.Sign(jwt.RegisteredClaims{
		Issuer:    "https://issuer.test",
		Subject:   "did:example:abc",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("sign with key A: %v", err)
	}

	s := &Service{issuer: verifier} // nil pool: signature fails before DB
	res, err := s.Verify(context.Background(), tokenA)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if res == nil || res.Valid {
		t.Errorf("a credential signed by a different key must NOT verify, got %+v", res)
	}
}
