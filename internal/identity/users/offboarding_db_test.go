//go:build integration

package user

import (
	"encoding/json"
	"maps"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// integrationsBy sets up, in tenant, one live integration of each kind that
// creator created, and returns their names by kind.
func integrationsBy(t *testing.T, tenant, creator uuid.UUID) map[string]string {
	t.Helper()
	names := map[string]string{
		"service_principal": dbtest.Unique("robot"),
		"scim_token":        dbtest.Unique("okta-scim"),
		"webhook":           "https://" + dbtest.Unique("hooks") + ".example.test/in",
		"auth_hook":         "https://" + dbtest.Unique("gate") + ".example.test/check",
		"oidc_client":       dbtest.Unique("payroll"),
	}
	exec(t, `INSERT INTO auth.service_principals (tenant_id, name, secret_hash, created_by) VALUES ($1, $2, 'hash', $3)`, tenant, names["service_principal"], creator)
	exec(t, `INSERT INTO tenant.scim_tokens (tenant_id, name, token_hash, token_prefix, created_by) VALUES ($1, $2, gen_random_uuid()::text, 'scim', $3)`, tenant, names["scim_token"], creator)
	exec(t, `INSERT INTO tenant.webhook_subscriptions (tenant_id, url, secret_ct, secret_nonce, created_by) VALUES ($1, $2, '\x00', '\x00', $3)`, tenant, names["webhook"], creator)
	exec(t, `INSERT INTO tenant.auth_hooks (tenant_id, url, secret_ct, secret_nonce, created_by) VALUES ($1, $2, '\x00', '\x00', $3)`, tenant, names["auth_hook"], creator)
	exec(t, `INSERT INTO auth.oidc_clients (tenant_id, client_id, name, created_by) VALUES ($1, gen_random_uuid()::text, $2, $3)`, tenant, names["oidc_client"], creator)
	return names
}

// leftIntegrations reads the integrations the critical event recorded when
// person was offboarded from tenant, by kind.
func leftIntegrations(t *testing.T, tenant, person uuid.UUID) map[string]string {
	t.Helper()
	var raw []byte
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT metadata->'integrations' FROM audit.events
		WHERE tenant_id = $1 AND action = 'user.integrations_left' AND resource_id = $2`, tenant, person).Scan(&raw); err != nil {
		t.Fatalf("the offboarding recorded no user.integrations_left event: %v", err)
	}
	var items []struct{ Kind, Name string }
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, it := range items {
		if _, twice := out[it.Kind]; twice {
			t.Errorf("%s listed twice", it.Kind)
		}
		out[it.Kind] = it.Name
	}
	return out
}

// TestOffboardingListsTheIntegrationsTheAdminCreated checks that deleting an
// administrator, or removing one from an organisation, records a critical
// event there listing every live integration they created in it, and only
// those, and revokes the admin-portal links and pending invitations they
// issued there; their integrations elsewhere are not listed.
func TestOffboardingListsTheIntegrationsTheAdminCreated(t *testing.T) {
	h := testHandler(t, nil)
	t.Run("deleted", func(t *testing.T) {
		tenant := dbtest.Tenant(t)
		owner := dbtest.User(t, tenant, tenant)
		admin := dbtest.User(t, tenant, tenant)
		want := integrationsBy(t, tenant, admin.ID)
		integrationsBy(t, tenant, owner.ID)
		exec(t, `INSERT INTO tenant.scim_tokens (tenant_id, name, token_hash, token_prefix, created_by, revoked_at) VALUES ($1, 'revoked', gen_random_uuid()::text, 'scim', $2, NOW())`, tenant, admin.ID)
		exec(t, `INSERT INTO tenant.admin_portal_links (tenant_id, token_hash, capabilities, created_by, expires_at) VALUES ($1, gen_random_uuid()::text, '{saml}', $2, NOW() + INTERVAL '1 day')`, tenant, admin.ID)
		exec(t, `INSERT INTO tenant.admin_portal_links (tenant_id, token_hash, capabilities, created_by, expires_at) VALUES ($1, gen_random_uuid()::text, '{saml}', $2, NOW() + INTERVAL '1 day')`, tenant, owner.ID)
		exec(t, `INSERT INTO tenant.invites (tenant_id, email, invited_by, token_hash, expires_at) VALUES ($1, $2, $3, gen_random_uuid()::text, NOW() + INTERVAL '1 day')`, tenant, dbtest.Unique("invitee")+"@example.test", admin.ID)
		exec(t, `INSERT INTO tenant.invites (tenant_id, email, invited_by, token_hash, expires_at) VALUES ($1, $2, $3, gen_random_uuid()::text, NOW() + INTERVAL '1 day')`, tenant, dbtest.Unique("invitee")+"@example.test", owner.ID)

		as := dbtest.Serve(dbtest.Principal(owner.ID, tenant), h.Mount)
		if rec := dbtest.Do(t, as, http.MethodDelete, "/users/"+admin.ID.String(), nil); rec.Code != http.StatusOK {
			t.Fatalf("delete the administrator: %d %s", rec.Code, rec.Body.String())
		}
		if got := leftIntegrations(t, tenant, admin.ID); !maps.Equal(got, want) {
			t.Errorf("integrations listed %v, want the administrator's live ones %v", got, want)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM tenant.admin_portal_links WHERE tenant_id = $1 AND revoked_at IS NULL AND created_by = $2`, tenant, admin.ID); n != 0 {
			t.Errorf("%d of the administrator's admin-portal links still work", n)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM tenant.invites WHERE tenant_id = $1 AND status = 'pending' AND invited_by = $2`, tenant, admin.ID); n != 0 {
			t.Errorf("%d of the administrator's invitations are still pending", n)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'user.integrations_left' AND resource_id = $2
			AND metadata->>'admin_portal_links_revoked' = '1' AND metadata->>'invitations_revoked' = '1'`, tenant, admin.ID); n != 1 {
			t.Errorf("the event doesn't say one admin-portal link and one invitation were revoked")
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM tenant.admin_portal_links WHERE tenant_id = $1 AND revoked_at IS NULL`, tenant) +
			dbtest.Count(t, `SELECT count(*) FROM tenant.invites WHERE tenant_id = $1 AND status = 'pending'`, tenant); n != 2 {
			t.Errorf("%d of the owner's link and invitation are left, want both", n)
		}
	})
	t.Run("removed from an organisation", func(t *testing.T) {
		home, tenant := dbtest.Tenant(t), dbtest.Tenant(t)
		admin := dbtest.User(t, tenant, tenant)
		member := dbtest.User(t, home, home, tenant)
		want := integrationsBy(t, tenant, member.ID)
		integrationsBy(t, home, member.ID)
		as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
		if rec := dbtest.Do(t, as, http.MethodDelete, "/users/"+member.ID.String()+"/membership", nil); rec.Code != http.StatusOK {
			t.Fatalf("remove the member: %d %s", rec.Code, rec.Body.String())
		}
		if got := leftIntegrations(t, tenant, member.ID); !maps.Equal(got, want) {
			t.Errorf("integrations listed %v, want those in the organisation %v", got, want)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'user.integrations_left'`, home); n != 0 {
			t.Errorf("their home organisation recorded %d offboarding events", n)
		}
	})
	t.Run("nothing created", func(t *testing.T) {
		tenant := dbtest.Tenant(t)
		owner := dbtest.User(t, tenant, tenant)
		admin := dbtest.User(t, tenant, tenant)
		as := dbtest.Serve(dbtest.Principal(owner.ID, tenant), h.Mount)
		if rec := dbtest.Do(t, as, http.MethodDelete, "/users/"+admin.ID.String(), nil); rec.Code != http.StatusOK {
			t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
		}
		if n := audited(t, tenant, "user.integrations_left", admin.ID); n != 0 {
			t.Errorf("%d offboarding events for someone who created nothing, want none", n)
		}
	})
}
