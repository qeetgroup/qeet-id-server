//go:build integration

package saml

// Database tests for service providers that sign in only the people assigned
// to them, and the routes that assign people and groups.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAssignedOnlySPSignsInWhoIsAssigned checks that an SP set to assigned
// people only signs in the people assigned to it, directly or through a
// group, refuses and audits anyone else, and signs in every member again once
// it is open.
func TestAssignedOnlySPSignsInWhoIsAssigned(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	alice, bob := dbtest.User(t, tenant), dbtest.User(t, tenant)
	aliceCookie, bobCookie := s.signIn(alice.ID), s.signIn(bob.ID)
	sp := spWith(t, ctx, s.idp, tenant, CreateSPInput{AssignmentRequired: true})
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: &Service{}, IdP: s.idp}).Mount)
	assignments := "/tenants/" + tenant.String() + "/saml-providers/" + sp.ID.String() + "/assignments"
	sso := func(cookie string) *httptest.ResponseRecorder {
		return idpGet(t, s.router, "/saml/idp/"+tenant.String()+"/sso?sp="+sp.ID.String(), cookie)
	}
	refused := func(who string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeSAMLSPNotAssigned) || strings.Contains(rec.Body.String(), "SAMLResponse") {
			t.Errorf("%s: %d %s, want 403 %s", who, rec.Code, rec.Body.String(), errs.CodeSAMLSPNotAssigned)
		}
	}
	change := func(method, path string, want int) {
		t.Helper()
		if rec := dbtest.Do(t, h, method, assignments+path, nil); rec.Code != want {
			t.Errorf("%s %s = %d %s, want %d", method, path, rec.Code, rec.Body.String(), want)
		}
	}

	refused("alice, unassigned", sso(aliceCookie))
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'saml.idp_assertion_refused'
		AND resource_id = $2 AND actor_user_id = $3 AND metadata->>'reason' = 'not_assigned'`, tenant, sp.ID, alice.ID); n != 1 {
		t.Errorf("%d refusals of alice audited, want 1", n)
	}
	req := httptest.NewRequest(http.MethodGet, "https://other.example/saml/idp/"+tenant.String()+"/sso?sp="+sp.ID.String(), nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: aliceCookie})
	page := httptest.NewRecorder()
	s.router.ServeHTTP(page, req)
	if page.Code != http.StatusForbidden || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(page.Body.String(), "access to this app") || !strings.Contains(page.Body.String(), errs.CodeSAMLSPNotAssigned) {
		t.Errorf("a browser refused: %d %q %s, want a page saying why", page.Code, page.Header().Get("Content-Type"), page.Body.String())
	}

	change(http.MethodPost, "/users/"+alice.ID.String(), http.StatusNoContent)
	change(http.MethodPost, "/users/"+alice.ID.String(), http.StatusNoContent)
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'saml.sp_user_assigned'
		AND resource_id = $2 AND actor_user_id = $3 AND metadata->>'user_id' = $4`, tenant, sp.ID, admin.ID, alice.ID.String()); n != 1 {
		t.Errorf("%d assignments of alice audited, want 1 however often she is assigned", n)
	}
	postedTo(t, sso(aliceCookie))
	refused("bob, unassigned", sso(bobCookie))

	engineering := newGroup(t, tenant, "Engineering", bob.ID)
	change(http.MethodPost, "/groups/"+engineering.String(), http.StatusNoContent)
	postedTo(t, sso(bobCookie))

	var list SPAssignments
	rec := dbtest.Do(t, h, http.MethodGet, assignments, nil)
	dbtest.Decode(t, rec, &list)
	if rec.Code != http.StatusOK || len(list.Users) != 1 || list.Users[0].UserID != alice.ID || list.Users[0].Email != alice.Email ||
		list.Users[0].AssignedBy == nil || *list.Users[0].AssignedBy != admin.ID || len(list.Groups) != 1 || list.Groups[0].Name != "Engineering" {
		t.Errorf("assignments = %d %s, want alice and Engineering, by the admin", rec.Code, rec.Body.String())
	}

	change(http.MethodDelete, "/users/"+alice.ID.String(), http.StatusNoContent)
	change(http.MethodDelete, "/users/"+alice.ID.String(), http.StatusNotFound)
	refused("alice, unassigned again", sso(aliceCookie))
	change(http.MethodDelete, "/users/"+bob.ID.String(), http.StatusNotFound)
	postedTo(t, sso(bobCookie))
	change(http.MethodDelete, "/groups/"+engineering.String(), http.StatusNoContent)
	refused("bob, his group unassigned", sso(bobCookie))
	for action, n := range map[string]int{"saml.sp_user_unassigned": 1, "saml.sp_group_assigned": 1, "saml.sp_group_unassigned": 1} {
		if got := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2 AND resource_id = $3`, tenant, action, sp.ID); got != n {
			t.Errorf("%d %s audited, want %d", got, action, n)
		}
	}

	open := false
	setOpen := UpdateSPInput{AssignmentRequired: &open}
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.idp.UpdateSP(ctx, tx, sp.ID, tenant, setOpen); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	postedTo(t, sso(aliceCookie))
}

// TestAssignmentsStayInTheirOrganisation checks that an organisation can
// assign only its own people and groups to its own service providers: another
// organisation's person, group or SP, and a guest whose home is elsewhere,
// are refused, and the database refuses a row that mixes organisations.
func TestAssignmentsStayInTheirOrganisation(t *testing.T) {
	ctx := dbtest.Context(t)
	idp, _ := newIdPRouter(t, sessionsByCookie{})
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	member := dbtest.User(t, tenant)
	guest := dbtest.User(t, other, tenant)
	outsider := dbtest.User(t, other, other)
	sp := spWith(t, ctx, idp, tenant, CreateSPInput{AssignmentRequired: true})
	theirSP := spWith(t, ctx, idp, other, CreateSPInput{AssignmentRequired: true})
	theirGroup := newGroup(t, other, "Theirs", outsider.ID)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: &Service{}, IdP: idp}).Mount)
	mine := "/tenants/" + tenant.String() + "/saml-providers/"

	for _, c := range []struct {
		name, method, path string
		status             int
		code               string
	}{
		{"another organisation's person", http.MethodPost, mine + sp.ID.String() + "/assignments/users/" + outsider.ID.String(), http.StatusNotFound, errs.CodeSAMLAssigneeNotFound},
		{"a guest whose home is elsewhere", http.MethodPost, mine + sp.ID.String() + "/assignments/users/" + guest.ID.String(), http.StatusNotFound, errs.CodeSAMLAssigneeNotFound},
		{"an unknown person", http.MethodPost, mine + sp.ID.String() + "/assignments/users/" + uuid.NewString(), http.StatusNotFound, errs.CodeSAMLAssigneeNotFound},
		{"another organisation's group", http.MethodPost, mine + sp.ID.String() + "/assignments/groups/" + theirGroup.String(), http.StatusNotFound, errs.CodeSAMLAssigneeNotFound},
		{"another organisation's SP", http.MethodPost, mine + theirSP.ID.String() + "/assignments/users/" + member.ID.String(), http.StatusNotFound, errs.CodeNotFound},
		{"another organisation's SP's list", http.MethodGet, mine + theirSP.ID.String() + "/assignments", http.StatusNotFound, errs.CodeNotFound},
		{"another organisation's SP, removing", http.MethodDelete, mine + theirSP.ID.String() + "/assignments/groups/" + theirGroup.String(), http.StatusNotFound, errs.CodeNotFound},
		{"another organisation's path", http.MethodPost, "/tenants/" + other.String() + "/saml-providers/" + theirSP.ID.String() + "/assignments/users/" + outsider.ID.String(), http.StatusForbidden, ""},
		{"a malformed person", http.MethodPost, mine + sp.ID.String() + "/assignments/users/not-a-uuid", http.StatusBadRequest, errs.CodeSAMLIDInvalid},
	} {
		rec := dbtest.Do(t, h, c.method, c.path, nil)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.code) {
			t.Errorf("%s: %d %s, want %d %s", c.name, rec.Code, rec.Body.String(), c.status, c.code)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.saml_sp_user_assignments WHERE sp_id IN ($1, $2)`, sp.ID, theirSP.ID) +
		dbtest.Count(t, `SELECT count(*) FROM tenant.saml_sp_group_assignments WHERE sp_id IN ($1, $2)`, sp.ID, theirSP.ID); n != 0 {
		t.Errorf("%d assignments made across organisations, want none", n)
	}

	for name, insert := range map[string]func() error{
		"another organisation's group": func() error {
			_, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO tenant.saml_sp_group_assignments (tenant_id, sp_id, group_id) VALUES ($1, $2, $3)`, tenant, sp.ID, theirGroup)
			return err
		},
		"another organisation's SP": func() error {
			_, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO tenant.saml_sp_user_assignments (tenant_id, sp_id, user_id) VALUES ($1, $2, $3)`, tenant, theirSP.ID, member.ID)
			return err
		},
		"another organisation's SP's persistent NameID": func() error {
			_, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO tenant.saml_idp_persistent_ids (tenant_id, sp_id, user_id, name_id) VALUES ($1, $2, $3, 'x')`, tenant, theirSP.ID, member.ID)
			return err
		},
	} {
		var pgErr *pgconn.PgError
		if err := insert(); !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Errorf("a row naming %s: %v, want a foreign key violation", name, err)
		}
	}
}
