//go:build integration

package user

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestBulkImportRowErrorsCarryCodes checks, against the database, that both
// bulk endpoints give every refused row its code and field, keep the message,
// and never show a failure's cause.
func TestBulkImportRowErrorsCarryCodes(t *testing.T) {
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	existing := dbtest.User(t, tenant, tenant)
	const policyCause = "dial tcp 10.0.0.5:5432: connection refused"
	h := &Handler{
		Repo:     NewRepository(pool),
		Validate: jsonNamedValidator(),
		PasswordPolicy: func(_ context.Context, _ uuid.UUID, _, plain string) error {
			switch plain {
			case "NoSymbolPassword99":
				return errs.ErrAuthPolicyPasswordNoSymbol
			case "PolicyStoreDown-99":
				return fmt.Errorf("authpolicy: load policy: %w", errors.New(policyCause))
			}
			return nil
		},
	}
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	created := dbtest.Unique("bulk") + "@example.test"
	noSymbol := dbtest.Unique("nosymbol") + "@example.test"
	policyDown := dbtest.Unique("down") + "@example.test"
	badPhone := dbtest.Unique("phone") + "@example.test"

	rec := dbtest.Do(t, as, http.MethodPost, "/users/bulk", map[string]any{"users": []map[string]any{
		{"email": created},
		{"email": "not-an-email"},
		{"email": existing.Email},
		{"email": noSymbol, "password": "NoSymbolPassword99"},
		{"email": policyDown, "password": "PolicyStoreDown-99"},
		{"email": badPhone, "phone": "555-0100"},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk create: status %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), policyCause) {
		t.Errorf("bulk create response shows the failure's cause: %s", rec.Body.String())
	}
	var res BulkImportResult
	dbtest.Decode(t, rec, &res)
	want := []BulkImportError{
		{Line: 2, Email: "not-an-email", Code: CodeImportFieldInvalid, Field: "email", Message: "invalid row: email failed email"},
		{Line: 3, Email: existing.Email, Code: errs.CodeAuthEmailExists, Field: "email", Message: "a user with this email already exists"},
		{Line: 4, Email: noSymbol, Code: errs.CodeAuthPolicyPasswordNoSymbol, Field: "password", Message: errs.ErrAuthPolicyPasswordNoSymbol.Message},
		{Line: 5, Email: policyDown, Code: errs.CodeInternal, Message: "could not create user"},
		{Line: 6, Email: badPhone, Code: CodeImportFieldInvalid, Field: "phone", Message: "invalid row: phone failed e164"},
	}
	if res.Succeeded != 1 || res.Failed != len(want) || len(res.Errors) != len(want) {
		t.Fatalf("bulk create result = %+v, want 1 created and %d refused", res, len(want))
	}
	for i, w := range want {
		if res.Errors[i] != w {
			t.Errorf("errors[%d] = %+v, want %+v", i, res.Errors[i], w)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE tenant_id = $1 AND email = $2`, tenant, created); n != 1 {
		t.Errorf("the valid row created %d users, want 1", n)
	}

	// Every row error of a vendor import names the line of the export file,
	// whether the adapter or the import refused it.
	importExport := func(source, export string) BulkImportResult {
		t.Helper()
		req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, "/users/bulk/import?source="+source, bytes.NewReader([]byte(export)))
		rec := httptest.NewRecorder()
		as.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s import: status %d (%s)", source, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "auth0Record") {
			t.Errorf("%s import response names an internal type: %s", source, rec.Body.String())
		}
		var res BulkImportResult
		dbtest.Decode(t, rec, &res)
		return res
	}
	for _, tc := range []struct {
		source, export string
		want           []BulkImportError
	}{
		{"auth0", strings.Join([]string{
			`{"email":"` + dbtest.Unique("auth0") + `@example.test"}`,
			`{"email":42}`,
			`{"name":"No Email"}`,
			`{"email":"` + existing.Email + `"}`,
		}, "\n"), []BulkImportError{
			{Line: 2, Code: CodeImportRowMalformed, Message: "invalid JSON"},
			{Line: 3, Code: CodeImportFieldMissing, Field: "email", Message: "missing email"},
			{Line: 4, Email: existing.Email, Code: errs.CodeAuthEmailExists, Field: "email", Message: "a user with this email already exists"},
		}},
		{"cognito", strings.Join([]string{
			"email,name",
			"",
			dbtest.Unique("cognito") + "@example.test,New",
			",Nobody",
			"not-an-email,Bad",
			existing.Email + ",Dupe",
		}, "\n"), []BulkImportError{
			{Line: 4, Code: CodeImportFieldMissing, Field: "email", Message: "missing email"},
			{Line: 5, Email: "not-an-email", Code: CodeImportFieldInvalid, Field: "email", Message: "invalid row: email failed email"},
			{Line: 6, Email: existing.Email, Code: errs.CodeAuthEmailExists, Field: "email", Message: "a user with this email already exists"},
		}},
	} {
		res := importExport(tc.source, tc.export)
		if res.Succeeded != 1 || res.Failed != len(tc.want) || len(res.Errors) != len(tc.want) {
			t.Fatalf("%s import result = %+v, want 1 created and %d refused", tc.source, res, len(tc.want))
		}
		for i, w := range tc.want {
			if res.Errors[i] != w {
				t.Errorf("%s errors[%d] = %+v, want %+v", tc.source, i, res.Errors[i], w)
			}
		}
	}
}

// fakeRoles gives roles as RoleGranter does, refusing when refuse is set.
type fakeRoles struct{ refuse error }

func (f fakeRoles) CheckGrant(*http.Request, uuid.UUID, uuid.UUID) (int, error) { return -1, f.refuse }

func (fakeRoles) Assign(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID, _ int) error {
	_, err := tx.Exec(ctx, `INSERT INTO rbac.user_roles (user_id, tenant_id, role_id, granted_by) VALUES ($1, $2, $3, $4)`, userID, tenantID, roleID, grantedBy)
	return err
}

// TestBulkImportGivesARoleAndReturnsIDs checks that a bulk import gives the
// role it names to every user it makes, with them in one transaction, returns
// their ids, and is refused whole when the role can't be given or isn't the
// organisation's.
func TestBulkImportGivesARoleAndReturnsIDs(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	var role, foreign uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'Member') RETURNING id`, tenant).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'Elsewhere') RETURNING id`, other).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	serve := func(roles RoleGranter) http.Handler {
		return dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator(), Roles: roles}).Mount)
	}
	rows := func(n int) []map[string]any {
		out := []map[string]any{}
		for range n {
			out = append(out, map[string]any{"email": dbtest.Unique("member") + "@example.test"})
		}
		return out
	}

	rec := dbtest.Do(t, serve(fakeRoles{}), http.MethodPost, "/users/bulk", map[string]any{"users": rows(2), "role_id": role})
	var res BulkImportResult
	dbtest.Decode(t, rec, &res)
	if rec.Code != http.StatusOK || res.Succeeded != 2 || len(res.Created) != 2 || res.Created[0].ID == uuid.Nil || res.Created[1].Line != 2 {
		t.Fatalf("import with a role: %d %+v; want both created with their ids", rec.Code, res)
	}
	for _, u := range res.Created {
		if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3`, u.ID, tenant, role); n != 1 {
			t.Errorf("%s has %d grants of the role, want 1", u.Email, n)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'role.assigned' AND metadata->>'source' = 'bulk_import'`, tenant); n != 2 {
		t.Errorf("%d role grants audited, want 2", n)
	}

	before := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE tenant_id = $1`, tenant)
	if rec := dbtest.Do(t, serve(fakeRoles{refuse: errs.ErrRBACGrantExceedsCaller}), http.MethodPost, "/users/bulk", map[string]any{"users": rows(1), "role_id": role}); rec.Code != http.StatusForbidden {
		t.Errorf("a role the caller can't give: %d, want 403", rec.Code)
	}
	if rec := dbtest.Do(t, serve(fakeRoles{}), http.MethodPost, "/users/bulk", map[string]any{"users": rows(1), "role_id": foreign}); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation's role: %d, want 404", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE tenant_id = $1`, tenant); n != before {
		t.Errorf("refused imports made %d users", n-before)
	}
	dbtest.Decode(t, dbtest.Do(t, serve(nil), http.MethodPost, "/users/bulk", map[string]any{"users": rows(1)}), &res)
	if len(res.Created) != 1 {
		t.Errorf("an import without a role: %+v, want its user's id", res)
	}
}
