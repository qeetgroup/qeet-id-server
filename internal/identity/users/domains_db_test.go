//go:build integration

package user

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestNoAccountsOnAnotherOrganisationsDomain checks that an organisation
// creates no account, alone or in bulk, on a domain another organisation has
// verified or below it, while its own domains and unclaimed ones stay open.
func TestNoAccountsOnAnotherOrganisationsDomain(t *testing.T) {
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	own, theirs := dbtest.Domain(t, tenant), dbtest.Domain(t, other)
	admin := dbtest.User(t, tenant, tenant)
	h := &Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator()}
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)

	for _, email := range []string{
		dbtest.Unique("a") + "@" + theirs,
		dbtest.Unique("a") + "@eu." + theirs,
		dbtest.Unique("a") + "@" + strings.ToUpper(theirs),
	} {
		if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": email}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeUserDomainManaged) {
			t.Errorf("create %s: %d %s, want 409 %s", email, rec.Code, rec.Body.String(), errs.CodeUserDomainManaged)
		}
	}
	for _, email := range []string{
		dbtest.Unique("a") + "@" + own,
		dbtest.Unique("a") + "@eu." + own,
		dbtest.Unique("a") + "@example.test",
	} {
		if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": email}); rec.Code != http.StatusCreated {
			t.Errorf("create %s: %d %s, want 201", email, rec.Code, rec.Body.String())
		}
	}

	claimed, open := dbtest.Unique("bulk")+"@"+theirs, dbtest.Unique("bulk")+"@"+own
	rec := dbtest.Do(t, as, http.MethodPost, "/users/bulk", map[string]any{"users": []map[string]any{{"email": claimed}, {"email": open}}})
	var res BulkImportResult
	dbtest.Decode(t, rec, &res)
	want := BulkImportError{Line: 1, Email: claimed, Code: errs.CodeUserDomainManaged, Field: "email", Message: errs.ErrUserDomainManaged.Message}
	if rec.Code != http.StatusOK || res.Succeeded != 1 || len(res.Errors) != 1 || res.Errors[0] != want {
		t.Errorf("bulk create: %d %+v, want the claimed row refused as %+v", rec.Code, res, want)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE tenant_id = $1 AND lower(email) LIKE '%' || $2`, tenant, theirs); n != 0 {
		t.Errorf("%d accounts created on another organisation's domain", n)
	}
}

// TestGuestOrganisationsDontSeeHomeMetadata checks that the metadata a
// person's home organisation keeps on them is shown to it, and not to an
// organisation they are only a guest in, whether read alone or in its list.
func TestGuestOrganisationsDontSeeHomeMetadata(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	home, guestOf := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, home, home, guestOf)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET metadata = '{"salary_band":"L7"}' WHERE id = $1`, person.ID); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator()}
	seen := func(tenant uuid.UUID) (single, listed string) {
		t.Helper()
		as := dbtest.Serve(dbtest.Principal(dbtest.User(t, tenant, tenant).ID, tenant), h.Mount)
		single = dbtest.Do(t, as, http.MethodGet, "/users/"+person.ID.String(), nil).Body.String()
		listed = dbtest.Do(t, as, http.MethodGet, "/users?limit=200", nil).Body.String()
		return single, listed
	}
	if single, listed := seen(home); !strings.Contains(single, "salary_band") || !strings.Contains(listed, "salary_band") {
		t.Errorf("the home organisation: %s / %s; want the metadata", single, listed)
	}
	if single, listed := seen(guestOf); strings.Contains(single, "salary_band") || strings.Contains(listed, "salary_band") || !strings.Contains(listed, person.Email) {
		t.Errorf("a guest organisation: %s / %s; want the person without the metadata", single, listed)
	}
}
