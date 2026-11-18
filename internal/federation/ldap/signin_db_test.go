//go:build integration

package ldap

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestLapsedPlanStopsLDAPSignIn checks that a connection set up while the plan
// included LDAP signs no one in once the plan has lapsed.
func TestLapsedPlanStopsLDAPSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	const userDN = "uid=alice,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{"cn=service,dc=example,dc=test": "service-secret", userDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: userDN, attrs: map[string]string{"mail": a.Email, "cn": "Alice"}}},
	}
	connID := storedConnection(t, organization, dir.start(t), "cn=service,dc=example,dc=test")
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := serviceOver(t, authSvc)
	svc.SetPlanGate(noLDAP{})

	if _, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test"); !errors.Is(err, errs.ErrUpgradeRequired) {
		t.Errorf("sign in after the plan lapsed: %v, want %v", err, errs.ErrUpgradeRequired)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d sessions after the plan lapsed, want none", n)
	}
}

// TestLoginAppliesSignInChecks checks that a directory sign-in adopts an
// existing account only once its address is verified, is held to the
// sign-in lockout, counted across spellings of one username, and answers with
// a challenge for an account that must use a second factor, as well as signing
// in an account that has none.
func TestLoginAppliesSignInChecks(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	a := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+dbtest.Domain(t, organization), organization, organization)
	const userDN = "uid=alice,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{"cn=service,dc=example,dc=test": "service-secret", userDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: userDN, attrs: map[string]string{"mail": a.Email, "cn": "Alice"}}},
	}
	connID := storedConnection(t, organization, dir.start(t), "cn=service,dc=example,dc=test")
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := serviceOver(t, authSvc)

	if _, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test"); !errors.Is(err, ErrAccountUnverified) {
		t.Errorf("adopt an account whose address isn't verified: %v, want %v", err, ErrAccountUnverified)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("verify the address: %v", err)
	}
	res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test")
	if err != nil || res.Pair == nil || res.Pair.UserID != a.ID || res.Pair.OrganizationID == nil || *res.Pair.OrganizationID != organization {
		t.Fatalf("sign in: %+v, %v", res, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE account.users SET mfa_required = TRUE WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("require MFA: %v", err)
	}
	res, err = svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test")
	if err != nil || res.Pair != nil || !res.MFARequired || res.MFAToken == "" {
		t.Errorf("sign in to an account that must use a second factor: %+v, %v; want a challenge", res, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET mfa_required = FALSE WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("lift MFA: %v", err)
	}

	for _, name := range []string{"alice", " alice", "ALICE", "alice  ", " Alice "} {
		if _, err := svc.Login(ctx, connID, name, "wrong", "192.0.2.20", "test"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password as %q: %v, want %v", name, err, ErrInvalidCredentials)
		}
	}
	if _, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test"); !errors.Is(err, errs.ErrAuthAccountLocked) {
		t.Errorf("right password after five wrong ones: %v, want %v", err, errs.ErrAuthAccountLocked)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID); n != 1 {
		t.Errorf("%d sessions, want only the first sign-in's", n)
	}
}

// TestLoginSpeaksOnlyForTheOrganization checks that a directory sign-in
// creates or adopts an account only on a domain the organization has
// verified, adopts no administrator by address, that a DN linked through one
// connection signs nobody in through another, and that a draft connection
// signs nobody in.
func TestLoginSpeaksOnlyForTheOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	admin := dbtest.UserAt(t, dbtest.Unique("root")+"@"+domain, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "policy.write"))
	newcomer := dbtest.Unique("alice") + "@" + domain
	const service, aliceDN, bobDN, rootDN = "cn=service,dc=example,dc=test", "uid=alice,dc=example,dc=test", "uid=bob,dc=example,dc=test", "uid=root,dc=example,dc=test"
	binds := map[string]string{service: "service-secret", aliceDN: "alice-secret", bobDN: "bob-secret", rootDN: "root-secret"}
	connect := func(entries map[string]dirEntry) uuid.UUID {
		dir := &directory{binds: binds, entries: entries}
		id := storedConnection(t, organization, dir.start(t), service)
		return id
	}
	conn := connect(map[string]dirEntry{
		"alice": {dn: aliceDN, attrs: map[string]string{"mail": newcomer, "cn": "Alice"}},
		"bob":   {dn: bobDN, attrs: map[string]string{"mail": dbtest.Unique("bob") + "@example.test", "cn": "Bob"}},
		"root":  {dn: rootDN, attrs: map[string]string{"mail": admin.Email, "cn": "Root"}},
	})
	rogue := connect(map[string]dirEntry{
		"alice": {dn: aliceDN, attrs: map[string]string{"mail": dbtest.Unique("rogue") + "@example.test", "cn": "Alice"}},
	})
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := serviceOver(t, authSvc)

	res, err := svc.Login(ctx, conn, "alice", "alice-secret", "192.0.2.21", "test")
	if err != nil || res.Pair == nil || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2 AND email = $3`, res.Pair.UserID, organization, newcomer) != 1 {
		t.Fatalf("a newcomer on the organization's domain: %+v, %v; want an account in it", res, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND connection_id = $2 AND subject = $3`, res.Pair.UserID, conn, aliceDN); n != 1 {
		t.Errorf("%d identities linked to the connection, want 1", n)
	}
	for _, c := range []struct {
		name     string
		conn     uuid.UUID
		username string
		want     error
	}{
		{"a newcomer on a domain nobody verified", conn, "bob", ErrEmailDomainUnverified},
		{"an administrator's address", conn, "root", ErrAccountAdministers},
		{"another connection's linked DN", rogue, "alice", ErrEmailDomainUnverified},
	} {
		if _, err := svc.Login(ctx, c.conn, c.username, c.username+"-secret", "192.0.2.21", "test"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, admin.ID); n != 0 {
		t.Errorf("the administrator was linked to the directory")
	}

	if _, err := pool.Exec(ctx, `UPDATE organization.ldap_connections SET status = 'draft' WHERE id = $1`, conn); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, conn, "alice", "alice-secret", "192.0.2.21", "test"); !errors.Is(err, ErrConnectionDraft) {
		t.Errorf("a sign-in through a draft connection: %v, want %v", err, ErrConnectionDraft)
	}
}

// TestLoginAdoptsADirectoryProvisionedAccount checks that an account the
// organization's directory provisioned over SCIM, its address never proved,
// signs in through the organization's LDAP connection.
func TestLoginAdoptsADirectoryProvisionedAccount(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	a := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+dbtest.Domain(t, organization), organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET provisioned_via = 'scim', email_verified_at = NULL WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	const userDN = "uid=alice,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{"cn=service,dc=example,dc=test": "service-secret", userDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: userDN, attrs: map[string]string{"mail": a.Email, "cn": "Alice"}}},
	}
	connID := storedConnection(t, organization, dir.start(t), "cn=service,dc=example,dc=test")
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	res, err := serviceOver(t, authSvc).Login(ctx, connID, "alice", "alice-secret", "192.0.2.22", "test")
	if err != nil || res.Pair == nil || res.Pair.UserID != a.ID {
		t.Fatalf("sign in: %+v, %v; want the provisioned account", res, err)
	}
}

// TestLoginSyncsGroupsAndName checks that each directory sign-in sets the
// person's display name and puts them in the groups their memberOf DNs are
// mapped to, comparing DNs ignoring case, and takes them out once the
// directory no longer lists the group.
func TestLoginSyncsGroupsAndName(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	email := dbtest.Unique("alice") + "@" + dbtest.Domain(t, organization)
	const service, userDN = "cn=service,dc=example,dc=test", "uid=alice,dc=example,dc=test"
	serve := func(entry dirEntry) string {
		dir := &directory{binds: map[string]string{service: "service-secret", userDN: "alice-secret"}, entries: map[string]dirEntry{"alice": entry}}
		return dir.start(t)
	}
	connID := storedConnection(t, organization, serve(dirEntry{dn: userDN, attrs: map[string]string{"mail": email, "cn": "Alice"},
		multi: map[string][]string{"memberOf": {"CN=Engineering,OU=Groups,DC=example,DC=test", "CN=Unmapped,OU=Groups,DC=example,DC=test"}}}), service)
	var engineering uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Engineering') RETURNING id`, organization).Scan(&engineering); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.sso_group_mappings (organization_id, connection_id, idp_group, group_id) VALUES ($1, $2, 'cn=engineering,ou=groups,dc=example,dc=test', $3)`, organization, connID, engineering); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := serviceOver(t, authSvc)

	res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.23", "test")
	if err != nil || res.Pair == nil {
		t.Fatalf("sign in: %+v, %v", res, err)
	}
	alice := res.Pair.UserID
	synced := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE organization_id = $1 AND group_id = $2 AND user_id = $3 AND source_connection_id = $4`,
			organization, engineering, alice, connID)
	}
	if synced() != 1 {
		t.Fatal("the sign-in didn't put the person in the group their memberOf is mapped to")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'group.member_added' AND resource_id = $2 AND actor_type = 'ldap'`, organization, engineering); n != 1 {
		t.Errorf("%d member_added events by the sign-in, want 1", n)
	}

	// The directory renames her and drops the group.
	if _, err := pool.Exec(ctx, `UPDATE organization.ldap_connections SET server_url = $2 WHERE id = $1`, connID,
		serve(dirEntry{dn: userDN, attrs: map[string]string{"mail": email, "cn": "Alice Smith"}})); err != nil {
		t.Fatal(err)
	}
	if res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.23", "test"); err != nil || res.Pair == nil || res.Pair.UserID != alice {
		t.Fatalf("sign in again: %+v, %v; want the same person", res, err)
	}
	if synced() != 0 {
		t.Error("the person is still in the group the directory no longer lists")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND display_name = 'Alice Smith'`, alice); n != 1 {
		t.Error("the sign-in didn't refresh the display name from the directory")
	}
}

// TestLoginProvisionsOnlyWithJIT checks that a directory sign-in creates an
// account only while the organization's domain has just-in-time provisioning
// on, and adopts an existing member's account either way.
func TestLoginProvisionsOnlyWithJIT(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	setJIT := func(on bool) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE organization.domains SET jit_enabled = $2 WHERE organization_id = $1`, organization, on); err != nil {
			t.Fatal(err)
		}
	}
	setJIT(false)
	member := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+domain, organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	newcomer := dbtest.Unique("bob") + "@" + domain
	const service, aliceDN, bobDN = "cn=service,dc=example,dc=test", "uid=alice,dc=example,dc=test", "uid=bob,dc=example,dc=test"
	dir := &directory{
		binds: map[string]string{service: "service-secret", aliceDN: "alice-secret", bobDN: "bob-secret"},
		entries: map[string]dirEntry{
			"alice": {dn: aliceDN, attrs: map[string]string{"mail": member.Email, "cn": "Alice"}},
			"bob":   {dn: bobDN, attrs: map[string]string{"mail": newcomer, "cn": "Bob"}},
		},
	}
	connID := storedConnection(t, organization, dir.start(t), service)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := serviceOver(t, authSvc)

	if res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.23", "test"); err != nil || res.Pair == nil || res.Pair.UserID != member.ID {
		t.Fatalf("adopt a member while the domain has JIT off: %+v, %v", res, err)
	}
	if _, err := svc.Login(ctx, connID, "bob", "bob-secret", "192.0.2.23", "test"); !errors.Is(err, ErrJITNotAllowed) {
		t.Errorf("a newcomer while the domain has JIT off: %v, want %v", err, ErrJITNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, newcomer); n != 0 {
		t.Fatal("a newcomer was provisioned while the domain has JIT off")
	}
	setJIT(true)
	res, err := svc.Login(ctx, connID, "bob", "bob-secret", "192.0.2.23", "test")
	if err != nil || res.Pair == nil || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2 AND email = $3`, res.Pair.UserID, organization, newcomer) != 1 {
		t.Errorf("a newcomer while the domain has JIT on: %+v, %v; want an account in the organization", res, err)
	}
}

// TestLDAPRecordsARefusedAdoption checks that a directory account the
// connection may not sign in by its address is recorded as a failed sign-in,
// with the reason, as every protocol records one: a refusal the lockout
// doesn't count is recorded all the same.
func TestLDAPRecordsARefusedAdoption(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.UserAt(t, dbtest.Unique("root")+"@"+dbtest.Domain(t, organization), organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "policy.write"))
	const service, rootDN = "cn=service,dc=example,dc=test", "uid=root,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{service: "service-secret", rootDN: "root-secret"},
		entries: map[string]dirEntry{"root": {dn: rootDN, attrs: map[string]string{"mail": admin.Email, "cn": "Root"}}},
	}
	conn := storedConnection(t, organization, dir.start(t), service)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := serviceOver(t, authSvc)

	if _, err := svc.Login(ctx, conn, "root", "root-secret", "192.0.2.30", "test"); !errors.Is(err, ErrAccountAdministers) {
		t.Fatalf("an administrator's address: %v, want %v", err, ErrAccountAdministers)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.sign_in_failed'
		AND metadata->>'method' = 'ldap' AND metadata->>'reason' = $2 AND metadata->>'connection_id' = $3 AND actor_user_id = $4`,
		organization, CodeAccountAdministers, conn.String(), admin.ID); n != 1 {
		t.Errorf("%d failed sign-ins recorded for the refused adoption, want 1", n)
	}
}

// TestLDAPRelinkRefreshesTheLinksAddress checks that a linked DN's next
// sign-in records the address the directory now holds on its link, as OpenID
// Connect sign-in does.
func TestLDAPRelinkRefreshesTheLinksAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	const service, aliceDN = "cn=service,dc=example,dc=test", "uid=alice,dc=example,dc=test"
	first, moved := dbtest.Unique("alice")+"@"+domain, dbtest.Unique("alice.rao")+"@"+domain
	dir := &directory{
		binds:   map[string]string{service: "service-secret", aliceDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: aliceDN, attrs: map[string]string{"mail": first, "cn": "Alice"}}},
	}
	conn := storedConnection(t, organization, dir.start(t), service)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := serviceOver(t, authSvc)

	res, err := svc.Login(ctx, conn, "alice", "alice-secret", "192.0.2.31", "test")
	if err != nil || res.Pair == nil {
		t.Fatalf("first sign-in: %+v, %v", res, err)
	}
	// The directory now holds another address for the same DN.
	changed := &directory{binds: dir.binds, entries: map[string]dirEntry{"alice": {dn: aliceDN, attrs: map[string]string{"mail": moved, "cn": "Alice"}}}}
	if _, err := pool.Exec(ctx, `UPDATE organization.ldap_connections SET server_url = $3 WHERE organization_id = $1 AND id = $2`, organization, conn, changed.start(t)); err != nil {
		t.Fatal(err)
	}
	again, err := svc.Login(ctx, conn, "alice", "alice-secret", "192.0.2.31", "test")
	if err != nil || again.Pair == nil || again.Pair.UserID != res.Pair.UserID {
		t.Fatalf("the linked DN's next sign-in: %+v, %v", again, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND subject = $2 AND email = $3`, res.Pair.UserID, aliceDN, moved); n != 1 {
		t.Errorf("the link doesn't hold the address the directory now holds")
	}
}
