//go:build integration

package audit

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestTheAuditLogIsFilteredAndCounted checks that the audit list narrows by
// several actions and resource types, a resource, an address and a time
// range, carries each event's metadata, and says how many match.
func TestTheAuditLogIsFilteredAndCounted(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	target := uuid.New()
	now := time.Now().UTC()
	insert := func(action, resourceType string, resourceID *uuid.UUID, ip string, at time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO audit.events (id, organization_id, actor_type, action, resource_type, resource_id, ip, created_at, metadata)
			VALUES ($1, $2, 'system', $3, $4, $5, NULLIF($6, '')::inet, $7, '{"note":"kept"}')`, id, organization, action, resourceType, resourceID, ip, at); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := insert("user.created", "user", nil, "", now.Add(-48*time.Hour))
	group := insert("group.updated", "group", &target, "203.0.113.5", now.Add(-time.Hour))
	role := insert("role.updated", "role", nil, "203.0.113.5", now.Add(-time.Minute))

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Reader: NewReader(dbtest.Pool(t))}).Mount)
	type page struct {
		Items []Row `json:"items"`
		Total int   `json:"total"`
	}
	get := func(v url.Values) page {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/audit?"+v.Encode(), nil)
		var p page
		dbtest.Decode(t, rec, &p)
		if rec.Code != http.StatusOK {
			t.Fatalf("audit %v: %d %s", v, rec.Code, rec.Body.String())
		}
		return p
	}
	ids := func(p page) []uuid.UUID {
		out := []uuid.UUID{}
		for _, r := range p.Items {
			out = append(out, r.ID)
		}
		return out
	}
	for name, c := range map[string]struct {
		query url.Values
		want  []uuid.UUID
	}{
		"several actions":        {url.Values{"action": {"group.updated,role.updated"}}, []uuid.UUID{role, group}},
		"several resource types": {url.Values{"resource_type": {"user,group"}}, []uuid.UUID{group, old}},
		"a resource":             {url.Values{"resource_id": {target.String()}}, []uuid.UUID{group}},
		"an address":             {url.Values{"ip": {"203.0.113.5"}}, []uuid.UUID{role, group}},
		"a time range":           {url.Values{"from": {now.Add(-2 * time.Hour).Format(time.RFC3339)}, "to": {now.Add(-30 * time.Minute).Format(time.RFC3339)}}, []uuid.UUID{group}},
	} {
		if got := get(c.query); !slices.Equal(ids(got), c.want) || got.Total != len(c.want) {
			t.Errorf("%s: %v of %d, want %v", name, ids(got), got.Total, c.want)
		}
	}
	first := get(url.Values{"limit": {"1"}})
	if len(first.Items) != 1 || first.Total != 3 || first.Items[0].Metadata["note"] != "kept" {
		t.Errorf("first page: %+v of %d, want one row with its metadata of 3", first.Items, first.Total)
	}
	for _, bad := range []url.Values{{"ip": {"nope"}}, {"resource_id": {"nope"}}, {"from": {"yesterday"}}} {
		if rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/audit?"+bad.Encode(), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("audit %v: %d, want 400", bad, rec.Code)
		}
	}
}

// unguarded serves mount as p with no organization-scope guard or row-level scope in
// front, so a handler that trusts the path's organization shows it.
func unguarded(p *httpx.Principal, mount func(chi.Router)) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
		})
	})
	mount(r)
	return r
}

// TestAuditListTakesTheOrganizationFromTheCaller checks that the audit list and
// its verification answer only for the caller's own organization, even without
// the router's organization guard in front: another organization's in the path is
// refused, not read.
func TestAuditListTakesTheOrganizationFromTheCaller(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mine, theirs := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, mine, mine)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(theirs, "secret.rotated", "key", uuid.New(), nil)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	h := unguarded(dbtest.Principal(admin.ID, mine), (&Handler{Reader: NewReader(pool), Verifier: NewVerifier(pool, nil)}).Mount)
	for _, path := range []string{"/organizations/" + theirs.String() + "/audit", "/organizations/" + theirs.String() + "/audit/verify"} {
		rec := dbtest.Do(t, h, http.MethodGet, path, nil)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "secret.rotated") {
			t.Errorf("GET %s as another organization: %d %.120s, want 403", path, rec.Code, rec.Body.String())
		}
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+mine.String()+"/audit", nil); rec.Code != http.StatusOK {
		t.Errorf("the caller's own audit list: %d %s", rec.Code, rec.Body.String())
	}
}

// TestAuditSearchFindsWords checks that a search finds the words of an
// action, its metadata, user agent and address, as prefixes, the actor by
// name or email, and still reads quoted phrases and exclusions: the searches
// the console found matched nothing.
func TestAuditSearchFindsWords(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	priya := dbtest.UserAt(t, dbtest.Unique("priya")+"@qeet.example", organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET display_name = 'Priya Rao' WHERE id = $1`, priya.ID); err != nil {
		t.Fatal(err)
	}
	insert := func(action, ua, ip, meta string, actor *uuid.UUID) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO audit.events (id, organization_id, actor_type, actor_user_id, action, resource_type, user_agent, ip, metadata)
			VALUES ($1, $2, 'user', $3, $4, 'session', $5, NULLIF($6, '')::inet, $7::jsonb)`, id, organization, actor, action, ua, ip, meta); err != nil {
			t.Fatal(err)
		}
		return id
	}
	login := insert("auth.login_succeeded", "Mozilla/5.0 (Macintosh)", "127.0.0.1", `{"method":"password"}`, &priya.ID)
	challenged := insert("auth.mfa_challenged", "curl/8.4.0", "198.51.100.2", `{"method":"totp"}`, nil)
	saml := insert("saml.login_succeeded", "", "", `{"risk":"low"}`, nil)

	h := dbtest.Serve(dbtest.Principal(priya.ID, organization), (&Handler{Reader: NewReader(pool)}).Mount)
	search := func(q string) []uuid.UUID {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/audit?q="+url.QueryEscape(q), nil)
		var page struct {
			Items []Row `json:"items"`
		}
		dbtest.Decode(t, rec, &page)
		if rec.Code != http.StatusOK {
			t.Fatalf("search %q: %d %s", q, rec.Code, rec.Body.String())
		}
		out := []uuid.UUID{}
		for _, r := range page.Items {
			out = append(out, r.ID)
		}
		slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
		return out
	}
	sorted := func(ids ...uuid.UUID) []uuid.UUID {
		slices.SortFunc(ids, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
		return ids
	}
	for q, want := range map[string][]uuid.UUID{
		"login":                {login, saml},
		"auth.login_succeeded": {login},
		"mfa_challenged":       {challenged},
		"password":             {login},
		"risk":                 {saml},
		"Mozilla":              {login},
		"127.0.0.1":            {login},
		priya.Email:            {login},
		"Priya":                {login},
		"succ":                 {login, saml},
		"login -saml":          {login},
		`"mfa challenged"`:     {challenged},
		"%":                    {},
	} {
		if got := search(q); !slices.Equal(got, sorted(want...)) {
			t.Errorf("search %q: %v, want %v", q, got, want)
		}
	}
}
