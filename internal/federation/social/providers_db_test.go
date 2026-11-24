//go:build integration

package social

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSocialProviderTrustChangeMustOutrankLinkedAdministrators checks that
// pointing an organization's OpenID Connect provider an owner is linked
// through at another discovery URL, by setting it up again or by changing it,
// is refused to someone who can change providers but doesn't outrank the
// owner, as it could then sign in as them, while other changes aren't, and an
// owner may make it.
func TestSocialProviderTrustChangeMustOutrankLinkedAdministrators(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	f := newSocialFixture(t)
	h := &Handler{Service: f.svc, ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	organization := dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, editor := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "connection.write", "connection.read"))
	as := func(a dbtest.Account, method, path string, body any) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, organization), h.Mount), method, path, body)
		return rec.Code, rec.Body.String()
	}
	discovery := f.idp.URL + "/.well-known/openid-configuration"
	provider := func(url string) map[string]string {
		return map[string]string{"provider": "corp", "client_id": "qeet", "client_secret": "idp-client-secret", "discovery_url": url}
	}
	if status, body := as(owner, http.MethodPost, "/social/providers", provider(discovery)); status != http.StatusOK {
		t.Fatalf("set the provider up: %d %s", status, body)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, subject) VALUES ($1, $2, 'corp', 'owner-subject')`, owner.ID, organization); err != nil {
		t.Fatal(err)
	}
	elsewhere := "https://idp.attacker.example/.well-known/openid-configuration"

	for name, c := range map[string]struct {
		method, path string
		body         any
	}{
		"sets the provider up again elsewhere": {http.MethodPost, "/social/providers", provider(elsewhere)},
		"changes its discovery URL":            {http.MethodPatch, "/social/providers/corp", map[string]string{"discovery_url": elsewhere}},
	} {
		if status, body := as(editor, c.method, c.path, c.body); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTrustChangeOutranks) {
			t.Errorf("an editor %s: %d %s, want 403 %s", name, status, body, errs.CodeRBACTrustChangeOutranks)
		}
	}
	for name, c := range map[string]struct {
		method, path string
		body         any
	}{
		"saves it unchanged":  {http.MethodPost, "/social/providers", provider(discovery)},
		"replaces its secret": {http.MethodPatch, "/social/providers/corp", map[string]any{"client_secret": "rotated-client-secret"}},
	} {
		if status, body := as(editor, c.method, c.path, c.body); status != http.StatusOK {
			t.Errorf("an editor %s: %d %s, want 200", name, status, body)
		}
	}
	if status, body := as(owner, http.MethodPatch, "/social/providers/corp", map[string]string{"discovery_url": f.idp.URL + "/v2/.well-known/openid-configuration"}); status != http.StatusOK {
		t.Errorf("an owner changes its discovery URL: %d %s, want 200", status, body)
	}
}
