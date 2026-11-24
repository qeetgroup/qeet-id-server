//go:build integration

package overview

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// every is every permission an area needs.
var every = []string{permConnections, permAPIKeys, permWebhooks, permPolicies, permMembers, permBilling}

// fill gives organization a little of everything the overview counts: what is
// in use and what isn't, so each count is seen to tell them apart.
func fill(t *testing.T, organization uuid.UUID) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	person, other := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	for _, stmt := range []string{
		`INSERT INTO organization.saml_connections (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
		 VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', 'active'),
		        ($1, 'Draft', '', '', '', 'draft')`,
		`INSERT INTO organization.ldap_connections (organization_id, name, server_url, bind_dn, base_dn, bind_password_ct, bind_password_nonce)
		 VALUES ($1, 'Directory', 'ldaps://ldap.example.test', 'cn=svc', 'dc=example', '\x00', '\x00')`,
		`INSERT INTO organization.oidc_connections (organization_id, name, issuer, client_id, client_secret_ct, client_secret_nonce, status)
		 VALUES ($1, 'Entra', 'https://login.example.test', 'client', '\x00', '\x00', 'active')`,
		`INSERT INTO organization.social_providers (organization_id, provider, client_id, client_secret_ct, client_secret_nonce, enabled)
		 VALUES ($1, 'google', 'g', '\x00', '\x00', TRUE), ($1, 'github', 'h', '\x00', '\x00', FALSE)`,
		`INSERT INTO organization.scim_tokens (organization_id, token_hash, token_prefix, revoked_at)
		 VALUES ($1, md5(random()::text), 'scim_a', NULL), ($1, md5(random()::text), 'scim_b', NOW())`,
		`INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, 'qci_' || md5(random()::text), 'App')`,
		`INSERT INTO organization.saml_service_providers (organization_id, name, entity_id, acs_url, status)
		 VALUES ($1, 'Wiki', 'https://wiki.example.test/' || md5(random()::text), 'https://wiki.example.test/acs', 'active')`,
		`INSERT INTO organization.domains (organization_id, domain, verification_token, verified_at, sso_enabled)
		 VALUES ($1, md5(random()::text) || '.example.test', 't1', NOW(), TRUE), ($1, md5(random()::text) || '.example.test', 't2', NULL, FALSE)`,
		`INSERT INTO organization.directory_events (id, organization_id, connection_id, operation, trigger_type, resource_type, started_at, duration_ms, http_status, status, resolution)
		 VALUES (gen_random_uuid(), $1, 'scim', 'user.create', 'push', 'user', NOW() - INTERVAL '1 hour', 5, 500, 'failed', 'open'),
		        (gen_random_uuid(), $1, 'scim', 'user.create', 'push', 'user', NOW() - INTERVAL '1 hour', 5, 500, 'failed', 'resolved'),
		        (gen_random_uuid(), $1, 'scim', 'user.create', 'push', 'user', NOW() - INTERVAL '10 days', 5, 500, 'failed', 'open')`,
		`INSERT INTO auth.api_keys (organization_id, name, prefix, key_hash, revoked_at)
		 VALUES ($1, 'CI', 'qk_a', md5(random()::text), NULL), ($1, 'Old', 'qk_b', md5(random()::text), NOW())`,
		`INSERT INTO organization.webhook_subscriptions (organization_id, url, secret_ct, secret_nonce, failing_since, disabled_at)
		 VALUES ($1, 'https://hooks.example.test/a', '\x00', '\x00', NOW(), NULL),
		        ($1, 'https://hooks.example.test/b', '\x00', '\x00', NULL, NOW())`,
		`INSERT INTO organization.security_policies (organization_id, mfa_enforcement) VALUES ($1, 'required')`,
		`INSERT INTO auth.abac_policies (organization_id, name, effect, resource_type, action, enabled)
		 VALUES ($1, 'p1', 'deny', 'document', 'read', TRUE), ($1, 'p2', 'allow', 'document', 'read', FALSE)`,
		`INSERT INTO auth.security_events (organization_id, type, status) VALUES ($1, 'lockout', 'open'), ($1, 'lockout', 'resolved')`,
		`INSERT INTO organization.invites (organization_id, email, token_hash, expires_at, status)
		 VALUES ($1, 'a@example.test', md5(random()::text), NOW() + INTERVAL '1 day', 'pending'),
		        ($1, 'b@example.test', md5(random()::text), NOW() - INTERVAL '1 day', 'pending')`,
		`UPDATE organization.organizations SET plan = 'pro' WHERE id = $1`,
	} {
		if _, err := pool.Exec(ctx, stmt, organization); err != nil {
			t.Fatalf("%v\n%s", err, stmt)
		}
	}
	for _, stmt := range []string{
		`INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at)
		 VALUES (md5(random()::text), 'qci_app', $2, $1, NOW() + INTERVAL '1 day'),
		        (md5(random()::text), 'qci_app', $2, $1, NOW() + INTERVAL '1 day'),
		        (md5(random()::text), 'qci_app', $3, $1, NOW() - INTERVAL '1 day')`,
		`INSERT INTO auth.trusted_devices (user_id, organization_id, token_hash, expires_at)
		 VALUES ($2, $1, md5(random()::text), NOW() + INTERVAL '1 day'), ($2, $1, md5(random()::text), NOW() + INTERVAL '1 day'),
		        ($3, $1, md5(random()::text), NOW() - INTERVAL '1 day')`,
	} {
		if _, err := pool.Exec(ctx, stmt, organization, person.ID, other.ID); err != nil {
			t.Fatalf("%v\n%s", err, stmt)
		}
	}
}

// TestOverviewCountsEachAreaOfTheOrganization checks every area's set-up state
// and counts, telling what is in use from what isn't, for the organization
// alone: another organization's things never count.
func TestOverviewCountsEachAreaOfTheOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	fill(t, organization)
	fill(t, other)
	svc, err := NewService(dbtest.Pool(t), allowOnly(every...), signInSettings{password: true, passkey: true, rememberDevice: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Overview(ctx, dbtest.Principal(uuid.New(), organization), organization)
	if err != nil {
		t.Fatal(err)
	}
	want := Overview{
		OrganizationID: organization, GeneratedAt: got.GeneratedAt,
		SingleSignOn:      &SingleSignOn{SAML: Count{2, 1}, LDAP: Count{1, 0}, OIDC: Count{1, 1}, SocialProviders: Count{2, 1}, SCIMTokensActive: 1},
		Applications:      &Applications{OIDCClients: 1, SAMLServiceProviders: Count{1, 1}, ActiveGrants: 2, PeopleWithGrants: 1},
		Domains:           &Domains{Total: 2, Verified: 1, SSORequired: 1},
		Directory:         &Directory{OpenErrors: 1},
		RememberedDevices: &RememberedDevices{Devices: 2, People: 1},
		APIKeys:           &APIKeys{Active: 1},
		Webhooks:          &Webhooks{Total: 2, Enabled: 1, Failing: 1},
		SignIn:            &SignIn{Password: true, Passkey: true, RememberDevice: true, MFAEnforcement: "required"},
		AccessPolicies:    &AccessPolicies{ABAC: Count{2, 1}},
		Threats:           &Threats{OpenAnomalies: 1},
		Invitations:       &Invitations{Pending: 1},
		Billing:           &Billing{Plan: "pro"},
	}
	for name, pair := range map[string][2]any{
		"single sign-on": {*got.SingleSignOn, *want.SingleSignOn}, "applications": {*got.Applications, *want.Applications},
		"domains": {*got.Domains, *want.Domains}, "directory": {*got.Directory, *want.Directory},
		"remembered devices": {*got.RememberedDevices, *want.RememberedDevices}, "api keys": {*got.APIKeys, *want.APIKeys},
		"webhooks": {*got.Webhooks, *want.Webhooks}, "sign-in": {*got.SignIn, *want.SignIn},
		"access policies": {*got.AccessPolicies, *want.AccessPolicies}, "threats": {*got.Threats, *want.Threats},
		"invitations": {*got.Invitations, *want.Invitations},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %+v, want %+v", name, pair[0], pair[1])
		}
	}
	if b := got.Billing; b.Plan != "pro" || b.SubscriptionStatus != nil || b.TrialEnd != nil || b.CurrentPeriodEnd != nil || b.CancelAtPeriodEnd {
		t.Errorf("billing = %+v, want the pro plan and no subscription", b)
	}

	fresh := dbtest.Organization(t)
	empty, err := svc.Overview(ctx, dbtest.Principal(uuid.New(), fresh), fresh)
	if err != nil {
		t.Fatal(err)
	}
	if *empty.SingleSignOn != (SingleSignOn{}) || *empty.Webhooks != (Webhooks{}) || empty.SignIn.MFAEnforcement != "optional" || empty.Billing.Plan != "free" {
		t.Errorf("a new organization's overview: %+v %+v %+v %+v; want nothing set up, MFA optional, the free plan",
			empty.SingleSignOn, empty.Webhooks, empty.SignIn, empty.Billing)
	}
}

// TestOverviewShowsOnlyWhatTheCallerMayRead checks that each area is answered
// only to a caller holding the permission its own list needs, and left out of
// the answer otherwise, down to an empty overview for someone holding none.
func TestOverviewShowsOnlyWhatTheCallerMayRead(t *testing.T) {
	organization := dbtest.Organization(t)
	fill(t, organization)
	areas := map[string][]string{
		permConnections: {"single_sign_on", "applications", "domains", "directory", "remembered_devices"},
		permAPIKeys:     {"api_keys"},
		permWebhooks:    {"webhooks"},
		permPolicies:    {"sign_in", "access_policies", "threats"},
		permMembers:     {"invitations"},
		permBilling:     {"billing"},
	}
	read := func(permissions ...string) string {
		t.Helper()
		svc, err := NewService(dbtest.Pool(t), allowOnly(permissions...), signInSettings{})
		if err != nil {
			t.Fatal(err)
		}
		h := dbtest.Serve(dbtest.Principal(uuid.New(), organization), (&Handler{Service: svc}).Mount)
		rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/overview", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("overview with %v: %d %s", permissions, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	for permission := range areas {
		body := read(permission)
		for other, otherKeys := range areas {
			for _, key := range otherKeys {
				if present := strings.Contains(body, `"`+key+`":`); present != (other == permission) {
					t.Errorf("holding only %s, %s present = %v: %s", permission, key, present, body)
				}
			}
		}
	}
	if body := read(); !strings.Contains(body, `"organization_id":"`+organization.String()+`"`) {
		t.Errorf("holding nothing: %s, want the organization and no area", body)
	} else {
		for _, keys := range areas {
			for _, key := range keys {
				if strings.Contains(body, `"`+key+`":`) {
					t.Errorf("holding nothing, %s is answered: %s", key, body)
				}
			}
		}
	}
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(uuid.New(), organization), (&Handler{Service: mustService(t)}).Mount),
		http.MethodGet, "/organizations/"+uuid.NewString()+"/overview", nil); rec.Code == http.StatusOK {
		t.Errorf("another organization's overview: %d, want refused", rec.Code)
	}
}

// mustService is a Service admitting every caller to every area.
func mustService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(dbtest.Pool(t), allowOnly(every...), signInSettings{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}
