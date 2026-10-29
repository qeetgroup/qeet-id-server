//go:build integration

package vc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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
		res, err := svc.Issue(ctx, tenant, IssueInput{Subject: "did:example:holder", Type: "EmployeeBadge", TTLSeconds: 3600}, audit.Actor{Type: "system"})
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
	if res := verify(revoked.JWT); res.Valid || res.Reason != "credential revoked" || res.ReasonCode != ReasonRevoked {
		t.Errorf("a revoked credential: %+v, want invalid: credential revoked", res)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM auth.credentials WHERE id = $1`, deleted.CredentialID); err != nil {
		t.Fatal(err)
	}
	if res := verify(deleted.JWT); res.Valid || res.Reason != "unknown credential" || res.ReasonCode != ReasonUnknown {
		t.Errorf("a credential with no record: %+v, want invalid: unknown credential", res)
	}
}

// TestCredentialsNameTheirHolder checks that a credential issued to a member
// of the organisation is listed with that person, that one issued to someone
// from another organisation is refused, and that the person is optional.
func TestCredentialsNameTheirHolder(t *testing.T) {
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	member := dbtest.User(t, tenant, tenant)
	outsider := dbtest.User(t, other, other)
	api := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	base := "/tenants/" + tenant.String() + "/credentials"

	issue := func(userID any) *httptest.ResponseRecorder {
		return dbtest.Do(t, api, http.MethodPost, base, map[string]any{
			"subject": "did:example:holder", "type": "EmployeeBadge", "user_id": userID,
		})
	}
	if rec := issue(member.ID); rec.Code != http.StatusCreated {
		t.Fatalf("issue to a member: %d %s", rec.Code, rec.Body.String())
	}
	if rec := issue(nil); rec.Code != http.StatusCreated {
		t.Fatalf("issue to no one: %d %s", rec.Code, rec.Body.String())
	}
	if rec := issue(outsider.ID); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), errs.CodeVCUserNotMember) {
		t.Errorf("issue to another organisation's person: %d %s, want 422 %s", rec.Code, rec.Body.String(), errs.CodeVCUserNotMember)
	}

	var list struct{ Items []Credential }
	dbtest.Decode(t, dbtest.Do(t, api, http.MethodGet, base, nil), &list)
	held := 0
	for _, c := range list.Items {
		if c.User != nil {
			held++
			if c.User.ID != member.ID || c.User.Email != member.Email {
				t.Errorf("a credential's holder: %+v, want %s", c.User, member.Email)
			}
		}
	}
	if len(list.Items) != 2 || held != 1 {
		t.Errorf("%d credentials, %d with a holder; want 2 and 1", len(list.Items), held)
	}
}
