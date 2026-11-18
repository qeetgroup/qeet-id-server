//go:build integration

package domainverify

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// captureService returns the service as bootstrap wires it for capture.
func captureService(t *testing.T) *Service {
	t.Helper()
	return newService(t)
}

// exec runs a statement for a test's setup.
func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// samlConnection adds a SAML connection with status to organization.
func samlConnection(t *testing.T, organization uuid.UUID, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO organization.saml_connections (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
		VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', $2) RETURNING id
	`, organization, status).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// ownerRole creates organization's owner role.
func ownerRole(t *testing.T, organization uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id
	`, organization).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// captured reports whether RefuseCaptured refuses email, failing on any other
// error and returning the connections a refusal names.
func captured(t *testing.T, svc *Service, email string) (bool, []map[string]any) {
	t.Helper()
	err := svc.RefuseCaptured(dbtest.Context(t), email)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Fatalf("RefuseCaptured(%s): %v", email, err)
	}
	conns, _ := errs.As(err).Metadata["connections"].([]map[string]any)
	return true, conns
}

// TestRefuseCaptured checks which addresses an organization's domain capture
// refuses: those it manages once SSO is on and it has an active SAML or LDAP
// connection, the same with or without an account; and not its break-glass
// members, nor the administrators single sign-on can't sign in, nor another
// organization's members or domains.
func TestRefuseCaptured(t *testing.T) {
	svc := captureService(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	nobody := dbtest.Unique("nobody") + "@" + strings.ToUpper(domain)
	team := "team." + domain
	exec(t, `INSERT INTO organization.domains (organization_id, domain, verification_token, verified_at, sso_enabled) VALUES ($1, $2, 'test', NOW(), TRUE)`, other, team)
	samlConnection(t, other, "active")
	exec(t, `INSERT INTO organization.ldap_connections (organization_id, name, server_url, bind_dn, bind_password_ct, bind_password_nonce, base_dn, status)
		VALUES ($1, 'Directory', 'ldaps://ldap.example.test', 'cn=service', '\x00', '\x00', 'dc=example', 'active')`, other)

	if got, _ := captured(t, svc, member.Email); got {
		t.Error("an address on a domain with SSO off is captured")
	}
	exec(t, `UPDATE organization.domains SET sso_enabled = TRUE WHERE organization_id = $1`, organization)
	samlConnection(t, organization, "draft")
	samlConnection(t, organization, "disabled")
	if got, _ := captured(t, svc, member.Email); got {
		t.Error("an address is captured while the organization has only a draft and a disabled connection")
	}
	active := samlConnection(t, organization, "active")

	for _, email := range []string{member.Email, nobody, dbtest.Unique("x") + "@eu." + domain} {
		got, conns := captured(t, svc, email)
		if !got || len(conns) != 1 || conns[0]["id"] != active || conns[0]["protocol"] != "saml" {
			t.Errorf("%s: captured %v naming %v; want refused, naming the active connection only", email, got, conns)
		}
	}
	// A closer domain another organization verified decides for itself, and an
	// address on no managed domain is nobody's.
	if got, conns := captured(t, svc, dbtest.Unique("x")+"@eu."+team); !got || len(conns) != 2 {
		t.Errorf("below the other organization's closer domain: captured %v naming %v; want its two connections", got, conns)
	}
	if got, _ := captured(t, svc, dbtest.Unique("x")+"@example.test"); got {
		t.Error("an address on no managed domain is captured")
	}

	// Break-glass members keep their methods while they are members; another
	// organization's mark doesn't count.
	exec(t, `INSERT INTO organization.break_glass_members (organization_id, user_id) VALUES ($1, $2)`, other, member.ID)
	if got, _ := captured(t, svc, member.Email); !got {
		t.Error("another organization's break-glass mark exempted the member")
	}
	exec(t, `INSERT INTO organization.break_glass_members (organization_id, user_id) VALUES ($1, $2)`, organization, member.ID)
	if got, _ := captured(t, svc, strings.ToUpper(member.Email)); got {
		t.Error("a break-glass member is captured")
	}
	guest := dbtest.UserAt(t, dbtest.Unique("guest")+"@"+domain, other, organization)
	exec(t, `INSERT INTO organization.break_glass_members (organization_id, user_id) VALUES ($1, $2)`, organization, guest.ID)
	if got, _ := captured(t, svc, guest.Email); got {
		t.Error("a break-glass guest member is captured")
	}
	exec(t, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, guest.ID, organization)
	if got, _ := captured(t, svc, guest.Email); !got {
		t.Error("a break-glass mark still exempts someone who has left the organization")
	}

	// An administrator single sign-on can't sign in keeps their methods until
	// an identity of theirs is linked to an active connection.
	admin := dbtest.UserAt(t, dbtest.Unique("admin")+"@"+domain, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "connection.write"))
	owner := dbtest.UserAt(t, dbtest.Unique("owner")+"@"+domain, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole(t, organization))
	for _, a := range []dbtest.Account{admin, owner} {
		if got, _ := captured(t, svc, a.Email); got {
			t.Errorf("%s, an administrator single sign-on can't sign in, is captured", a.Email)
		}
	}
	exec(t, `INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject, email) VALUES ($1, $2, 'saml', $3, 'okta|admin', $4)`,
		admin.ID, organization, active, admin.Email)
	if got, _ := captured(t, svc, admin.Email); !got {
		t.Error("an administrator linked to an active connection is not captured")
	}
	exec(t, `UPDATE organization.saml_connections SET status = 'disabled' WHERE id = $1`, active)
	if got, _ := captured(t, svc, nobody); got {
		t.Error("an address is captured once the organization's last active connection is off")
	}
}

// TestBreakGlassMembers checks that only an owner, in person, names and
// removes break-glass members, each change audited once; that only a member
// can be one; and that another organization can neither see nor change them.
func TestBreakGlassMembers(t *testing.T) {
	svc := captureService(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	owner := dbtest.User(t, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole(t, organization))
	admin := dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "connection.write"))
	member := dbtest.User(t, organization, organization)
	outsider := dbtest.User(t, other, other)
	otherOwner := dbtest.User(t, other)
	dbtest.Assign(t, otherOwner.ID, other, ownerRole(t, other))
	mount := (&Handler{Service: svc}).Mount
	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, organization), mount)
	base := "/organizations/" + organization.String() + "/break-glass-members"
	audited := func(action string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3`, organization, action, member.ID)
	}

	key := dbtest.Principal(owner.ID, organization)
	key.ActorType = "api_key"
	for name, h := range map[string]http.Handler{
		"an admin who isn't an owner":      dbtest.Serve(dbtest.Principal(admin.ID, organization), mount),
		"an owner's API key":               dbtest.Serve(key, mount),
		"a member who is no administrator": dbtest.Serve(dbtest.Principal(member.ID, organization), mount),
	} {
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			if rec := dbtest.Do(t, h, method, base+"/"+member.ID.String(), nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeRBACOwnerOnly) {
				t.Errorf("%s %s: %d %s, want 403 %s", name, method, rec.Code, rec.Body.String(), errs.CodeRBACOwnerOnly)
			}
		}
	}

	for i := 0; i < 2; i++ {
		if rec := dbtest.Do(t, asOwner, http.MethodPut, base+"/"+member.ID.String(), nil); rec.Code != http.StatusNoContent {
			t.Fatalf("the owner adds a member: %d %s", rec.Code, rec.Body.String())
		}
	}
	if n := audited("domain.break_glass_added"); n != 1 {
		t.Errorf("%d domain.break_glass_added events after adding twice, want 1", n)
	}
	rec := dbtest.Do(t, asOwner, http.MethodGet, base, nil)
	var list struct {
		Items []BreakGlassMember `json:"items"`
	}
	if dbtest.Decode(t, rec, &list); rec.Code != http.StatusOK || len(list.Items) != 1 ||
		list.Items[0].UserID != member.ID || list.Items[0].Email != member.Email || list.Items[0].CreatedBy == nil || *list.Items[0].CreatedBy != owner.ID {
		t.Errorf("list: %d %s; want the member, added by the owner", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOwner, http.MethodPut, base+"/"+outsider.ID.String(), nil); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), CodeNotMember) {
		t.Errorf("another organization's member: %d %s, want 404 %s", rec.Code, rec.Body.String(), CodeNotMember)
	}
	if rec := dbtest.Do(t, asOwner, http.MethodPut, base+"/not-a-uuid", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a malformed user id: %d, want 400", rec.Code)
	}

	// Another organization's owner: not in this organization's routes, and a
	// member of this one isn't theirs to name.
	asOther := dbtest.Serve(dbtest.Principal(otherOwner.ID, other), mount)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		path := base
		if method != http.MethodGet {
			path += "/" + member.ID.String()
		}
		if rec := dbtest.Do(t, asOther, method, path, nil); rec.Code != http.StatusForbidden {
			t.Errorf("another organization's owner %s %s: %d, want 403", method, path, rec.Code)
		}
	}
	otherBase := "/organizations/" + other.String() + "/break-glass-members"
	if rec := dbtest.Do(t, asOther, http.MethodPut, otherBase+"/"+member.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization's owner naming this organization's member: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if ids := breakGlassIDs(t, dbtest.Do(t, asOther, http.MethodGet, otherBase, nil)); slices.Contains(ids, member.ID) {
		t.Error("another organization's list shows this organization's break-glass member")
	}
	if rec := dbtest.Do(t, asOther, http.MethodDelete, otherBase+"/"+member.ID.String(), nil); rec.Code != http.StatusNoContent ||
		dbtest.Count(t, `SELECT count(*) FROM organization.break_glass_members WHERE organization_id = $1 AND user_id = $2`, organization, member.ID) != 1 {
		t.Errorf("another organization's owner removing in their own organization: %d; want 204 and this organization's mark kept", rec.Code)
	}

	for i := 0; i < 2; i++ {
		if rec := dbtest.Do(t, asOwner, http.MethodDelete, base+"/"+member.ID.String(), nil); rec.Code != http.StatusNoContent {
			t.Fatalf("the owner removes the member: %d %s", rec.Code, rec.Body.String())
		}
	}
	if n := audited("domain.break_glass_removed"); n != 1 {
		t.Errorf("%d domain.break_glass_removed events after removing twice, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.break_glass_members WHERE organization_id = $1`, organization); n != 0 {
		t.Errorf("%d break-glass members left, want none", n)
	}
}

// breakGlassIDs returns the user_id of every listed break-glass member.
func breakGlassIDs(t *testing.T, rec *httptest.ResponseRecorder) []uuid.UUID {
	t.Helper()
	var list struct {
		Items []BreakGlassMember `json:"items"`
	}
	dbtest.Decode(t, rec, &list)
	ids := make([]uuid.UUID, len(list.Items))
	for i, m := range list.Items {
		ids[i] = m.UserID
	}
	return ids
}

// oidcConnection adds an OpenID Connect connection with status to organization.
func oidcConnection(t *testing.T, organization uuid.UUID, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO organization.oidc_connections (organization_id, name, issuer, client_id, client_secret_ct, client_secret_nonce, status)
		VALUES ($1, 'Entra ID', 'https://login.example.test', 'client', '\x00', '\x00', $2) RETURNING id
	`, organization, status).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestOIDCConnectionsCapture checks that an active OpenID Connect connection
// captures its organization's domain as SAML and LDAP do, named as protocol
// oidc, and that an administrator linked to it is captured.
func TestOIDCConnectionsCapture(t *testing.T) {
	svc := captureService(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	exec(t, `UPDATE organization.domains SET sso_enabled = TRUE WHERE organization_id = $1`, organization)
	oidcConnection(t, organization, "draft")
	if got, _ := captured(t, svc, dbtest.Unique("x")+"@"+domain); got {
		t.Error("an address is captured while the organization's only OpenID Connect connection is a draft")
	}
	active := oidcConnection(t, organization, "active")
	if got, conns := captured(t, svc, dbtest.Unique("x")+"@"+domain); !got || len(conns) != 1 || conns[0]["id"] != active || conns[0]["protocol"] != "oidc" {
		t.Errorf("with an active OpenID Connect connection: captured %v naming %v; want it, as oidc", got, conns)
	}
	admin := dbtest.UserAt(t, dbtest.Unique("admin")+"@"+domain, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "connection.write"))
	if got, _ := captured(t, svc, admin.Email); got {
		t.Error("an unlinked administrator is captured")
	}
	exec(t, `INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject, email) VALUES ($1, $2, 'oidc', $3, 'entra|admin', $4)`,
		admin.ID, organization, active, admin.Email)
	if got, _ := captured(t, svc, admin.Email); !got {
		t.Error("an administrator linked to an active OpenID Connect connection is not captured")
	}
}

// TestDiscoverRoutesByDomainAlone checks that discovery names a domain's
// active connections with where each signs in once SSO is on for it, gives
// every address on the domain the same answer, break-glass members included,
// and routes nothing for a domain with SSO off or one nobody manages.
func TestDiscoverRoutesByDomainAlone(t *testing.T) {
	svc := captureService(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	saml := samlConnection(t, organization, "active")
	samlConnection(t, organization, "draft")
	h := httptest.NewServer(func() http.Handler {
		r := chi.NewRouter()
		(&Handler{Service: svc}).MountPublic(r)
		return r
	}())
	defer h.Close()

	if d, err := svc.Discover(dbtest.Context(t), member.Email); err != nil || d.SSO || len(d.Connections) != 0 {
		t.Errorf("a domain with SSO off: %+v, %v; want not routed", d, err)
	}
	exec(t, `UPDATE organization.domains SET sso_enabled = TRUE WHERE organization_id = $1`, organization)
	exec(t, `INSERT INTO organization.break_glass_members (organization_id, user_id) VALUES ($1, $2)`, organization, member.ID)
	var ldap uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `INSERT INTO organization.ldap_connections (organization_id, name, server_url, bind_dn, bind_password_ct, bind_password_nonce, base_dn, status)
		VALUES ($1, 'Directory', 'ldaps://ldap.example.test', 'cn=service', '\x00', '\x00', 'dc=example', 'active') RETURNING id`, organization).Scan(&ldap); err != nil {
		t.Fatal(err)
	}
	want := []DiscoveredConnection{
		{ID: saml, Protocol: "saml", Name: "Okta", Method: "redirect", LoginPath: "/saml/login/" + saml.String()},
		{ID: ldap, Protocol: "ldap", Name: "Directory", Method: "credentials", LoginPath: "/ldap/" + ldap.String() + "/authenticate", SessionPath: "/ldap/" + ldap.String() + "/session"},
	}
	var orgName string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT name FROM organization.organizations WHERE id = $1`, organization).Scan(&orgName); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{member.Email, dbtest.Unique("nobody") + "@" + strings.ToUpper(domain)} {
		d, err := svc.Discover(dbtest.Context(t), email)
		if err != nil || !d.SSO || !slices.Equal(d.Connections, want) || d.Organization != orgName {
			t.Errorf("%s: %+v, %v; want routed to %+v by %q", email, d, err, want, orgName)
		}
	}
	if d, err := svc.Discover(dbtest.Context(t), dbtest.Unique("x")+"@example.test"); err != nil || d.SSO {
		t.Errorf("a domain nobody manages: %+v, %v; want not routed", d, err)
	}

	for body, want := range map[string]int{`{"email":"` + member.Email + `"}`: http.StatusOK, `{"email":"no-at-sign"}`: http.StatusUnprocessableEntity} {
		resp, err := http.Post(h.URL+"/sso/discovery", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("POST /sso/discovery %s: %d, want %d", body, resp.StatusCode, want)
		}
	}
}

// TestCaptureLeavesEveryAdministratorTheirMethods checks that a member holding
// any permission outside the member allowlist, such as only gdpr.write, keeps
// their own sign-in methods on a captured domain until linked, while one
// holding only allowlisted reads is captured.
func TestCaptureLeavesEveryAdministratorTheirMethods(t *testing.T) {
	svc := captureService(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	exec(t, `UPDATE organization.domains SET sso_enabled = TRUE WHERE organization_id = $1`, organization)
	samlConnection(t, organization, "active")
	for _, key := range []string{"gdpr.write", "secret.read", "billing.write", "branding.write"} {
		officer := dbtest.UserAt(t, dbtest.Unique("officer")+"@"+domain, organization)
		dbtest.Assign(t, officer.ID, organization, dbtest.Role(t, organization, key))
		if got, _ := captured(t, svc, officer.Email); got {
			t.Errorf("a member holding %s, an administrator, is captured", key)
		}
	}
	reader := dbtest.UserAt(t, dbtest.Unique("reader")+"@"+domain, organization)
	dbtest.Assign(t, reader.ID, organization, dbtest.Role(t, organization, "audit.read", "user.read"))
	if got, _ := captured(t, svc, reader.Email); !got {
		t.Error("a member holding only reads is not captured")
	}
}
