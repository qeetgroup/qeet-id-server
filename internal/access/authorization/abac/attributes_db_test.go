//go:build integration

package abac

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPlatformAttributes checks that the platform names a person's groups and
// roles in the organization decided in, direct and through a group, and none
// from another; that context.mfa says whether their session met a second
// factor or holds a fresh step-up, and is left out for a session it can't
// read; and that ip is the call's address.
func TestPlatformAttributes(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization)
	dbtest.Assign(t, person.ID, organization, namedRole(t, organization, "Billing Admin"))
	dbtest.Assign(t, person.ID, other, namedRole(t, other, "Elsewhere"))
	group(t, organization, "Finance", []uuid.UUID{namedRole(t, organization, "Auditor")}, person.ID)
	group(t, organization, "Contractors", nil)
	group(t, other, "Other Team", nil, person.ID)

	subject, ctxAttrs, err := svc.PlatformAttributes(ctx, Request{Subject: person.ID.String(), UserID: person.ID, OrganizationID: organization, IP: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(subject["groups"], subject["roles"]); got != "[Finance] [Auditor Billing Admin]" {
		t.Errorf("groups and roles %s, want this organization's only", got)
	}
	if subject["id"] != person.ID.String() || subject["organization_id"] != organization.String() || ctxAttrs["ip"] != "203.0.113.7" {
		t.Errorf("subject %v, context %v; want the person, the organization and the address", subject, ctxAttrs)
	}
	if _, ok := ctxAttrs["mfa"]; ok {
		t.Errorf("context %v: mfa without a session", ctxAttrs)
	}

	stepped := session(t, person.ID, organization, "")
	if _, err := pool.Exec(ctx, `INSERT INTO auth.mfa_verifications (user_id, session_id, method) VALUES ($1, $2, 'totp')`, person.ID, stepped); err != nil {
		t.Fatal(err)
	}
	revoked := session(t, person.ID, organization, "passkey")
	if _, err := pool.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1`, revoked); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		r       Request
		want    any
		present bool
	}{
		{"a passkey sign-in", Request{SessionID: session(t, person.ID, organization, "passkey")}, true, true},
		{"a remembered device", Request{SessionID: session(t, person.ID, organization, "trusted_device")}, true, true},
		{"no second factor", Request{SessionID: session(t, person.ID, organization, "")}, false, true},
		{"a fresh step-up", Request{SessionID: stepped}, true, true},
		{"a hosted-login call that proved one", Request{MFA: true}, true, true},
		{"a revoked session", Request{SessionID: revoked}, nil, false},
		{"another organization's session", Request{SessionID: session(t, person.ID, other, "passkey")}, nil, false},
	} {
		tc.r.Subject, tc.r.UserID, tc.r.OrganizationID = person.ID.String(), person.ID, organization
		_, ctxAttrs, err := svc.PlatformAttributes(ctx, tc.r)
		if mfa, ok := ctxAttrs["mfa"]; err != nil || ok != tc.present || mfa != tc.want {
			t.Errorf("%s: context %v, %v; want mfa %v (present %v)", tc.name, ctxAttrs, err, tc.want, tc.present)
		}
	}
}
