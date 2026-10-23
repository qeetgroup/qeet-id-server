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
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE tenant_id = $1 AND email = $2`, tenant, created); n != 1 {
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
