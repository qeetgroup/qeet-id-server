//go:build integration

package audit

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

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
		rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/audit?q="+url.QueryEscape(q), nil)
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
