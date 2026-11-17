//go:build integration

package decide_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// requestAs is the context of a request from addr made as p, as the router
// gives it to the route guard.
func requestAs(p *httpx.Principal, addr string) context.Context {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/v1/users/x", nil)
	req.RemoteAddr = addr + ":40000"
	var got context.Context
	httpx.ClientIPContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Context() })).ServeHTTP(httptest.NewRecorder(), req)
	return httpx.WithPrincipal(got, p)
}

// TestRouteGuardDecidesOnTheCallersAttributes checks that the route guard
// holds the console's "require MFA" template, refusing a deletion to a session
// without a second factor and to an application's token and allowing it to a
// session that met one, and that a deny on a group refuses its members only.
func TestRouteGuardDecidesOnTheCallersAttributes(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin, contractor := dbtest.User(t, organization), dbtest.User(t, organization)
	role := dbtest.Role(t, organization, "user.delete", "user.read")
	dbtest.Assign(t, admin.ID, organization, role)
	dbtest.Assign(t, contractor.ID, organization, role)
	var group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Contractors') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, group, contractor.ID, organization); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string][3]string{
		"require_mfa_sensitive": {"*", "delete", `{"all":[{"attr":"context.mfa","op":"ne","value":"true"}]}`},
		"no_contractors":        {"user", "*", `{"attr":"subject.groups","op":"contains","value":"Contractors"}`},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO auth.abac_policies (organization_id, name, effect, resource_type, action, condition) VALUES ($1, $2, 'deny', $3, $4, $5)`,
			organization, name, p[0], p[1], p[2]); err != nil {
			t.Fatal(err)
		}
	}
	session := func(user uuid.UUID, factor string) *uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO auth.sessions (user_id, organization_id, second_factor) VALUES ($1, $2, NULLIF($3, '')) RETURNING id`, user, organization, factor).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return &id
	}
	caller := func(user uuid.UUID, sessionID *uuid.UUID, clientID string) *httpx.Principal {
		return &httpx.Principal{UserID: &user, OrganizationID: &organization, ActorType: "user", SessionID: sessionID, ClientID: clientID}
	}

	d := decide.New(rbac.NewRepository(pool), rebac.NewService(pool), abac.NewService(pool))
	for _, tc := range []struct {
		name       string
		p          *httpx.Principal
		permission string
		want       bool
	}{
		{"a deletion in a session that met a second factor", caller(admin.ID, session(admin.ID, "passkey"), ""), "user.delete", true},
		{"a deletion in a session that didn't", caller(admin.ID, session(admin.ID, ""), ""), "user.delete", false},
		{"a deletion with an application's token", caller(admin.ID, session(admin.ID, "passkey"), "qci_app"), "user.delete", false},
		{"a read in a session that didn't meet one", caller(admin.ID, session(admin.ID, ""), ""), "user.read", true},
		{"a read by a contractor", caller(contractor.ID, session(contractor.ID, "passkey"), ""), "user.read", false},
	} {
		got, err := d.Check(requestAs(tc.p, "203.0.113.7"), *tc.p.UserID, organization, tc.permission)
		if err != nil || got != tc.want {
			t.Errorf("%s: allowed %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
}
