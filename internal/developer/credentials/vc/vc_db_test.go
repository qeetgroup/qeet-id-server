//go:build integration

package vc

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestVerifyChecksTheRegistry checks that a credential verifies while its
// record stands, and is refused once revoked or once the record is gone.
func TestVerifyChecksTheRegistry(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	issue := func() *IssueResult {
		t.Helper()
		res, err := svc.Issue(ctx, tenant, "did:example:holder", "EmployeeBadge", nil, 3600, audit.Actor{Type: "system"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return res
	}
	verify := func(raw string) *VerifyResult {
		t.Helper()
		res, err := svc.Verify(ctx, raw)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return res
	}

	revoked, deleted := issue(), issue()
	if res := verify(revoked.JWT); !res.Valid {
		t.Fatalf("a standing credential is refused: %+v", res)
	}
	if err := svc.Revoke(ctx, revoked.CredentialID, tenant, audit.Actor{Type: "system"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res := verify(revoked.JWT); res.Valid || res.Reason != "credential revoked" {
		t.Errorf("a revoked credential: %+v, want invalid: credential revoked", res)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM auth.credentials WHERE id = $1`, deleted.CredentialID); err != nil {
		t.Fatal(err)
	}
	if res := verify(deleted.JWT); res.Valid || res.Reason != "unknown credential" {
		t.Errorf("a credential with no record: %+v, want invalid: unknown credential", res)
	}
}
