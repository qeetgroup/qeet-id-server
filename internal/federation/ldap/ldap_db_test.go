//go:build integration

package ldap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// directory is a minimal LDAPv3 server for tests: simple binds checked against
// binds (DN to password), and searches answered from entries (uid to the
// entry's DN and attributes).
type directory struct {
	binds   map[string]string
	entries map[string]dirEntry
}

type dirEntry struct {
	dn    string
	attrs map[string]string
	multi map[string][]string // attributes with several values, such as memberOf
}

// start serves d on a loopback port until t ends and returns its ldap:// URL.
func (d *directory) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(conn)
		}
	}()
	return "ldap://" + ln.Addr().String()
}

func (d *directory) serve(conn net.Conn) {
	defer conn.Close()
	for {
		p, err := ber.ReadPacket(conn)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		var replies []*ber.Packet
		switch op.Tag {
		case goldap.ApplicationBindRequest:
			dn, _ := op.Children[1].Value.(string)
			code := goldap.LDAPResultInvalidCredentials
			if want, ok := d.binds[dn]; ok && want == op.Children[2].Data.String() {
				code = goldap.LDAPResultSuccess
			}
			replies = append(replies, ldapResult(goldap.ApplicationBindResponse, code))
		case goldap.ApplicationSearchRequest:
			filter, _ := goldap.DecompileFilter(op.Children[6])
			uid := strings.TrimSuffix(strings.TrimPrefix(filter, "(uid="), ")")
			if e, ok := d.entries[uid]; ok {
				replies = append(replies, ldapEntry(e))
			}
			replies = append(replies, ldapResult(goldap.ApplicationSearchResultDone, goldap.LDAPResultSuccess))
		default:
			return
		}
		for _, reply := range replies {
			msg := ber.NewSequence("")
			msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
			msg.AppendChild(reply)
			if _, err := conn.Write(msg.Bytes()); err != nil {
				return
			}
		}
	}
}

func ldapResult(tag ber.Tag, code int) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	return op
}

func ldapEntry(e dirEntry) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, goldap.ApplicationSearchResultEntry, nil, "")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, ""))
	attrs := ber.NewSequence("")
	all := map[string][]string{}
	for name, value := range e.attrs {
		all[name] = []string{value}
	}
	for name, values := range e.multi {
		all[name] = values
	}
	for name, vs := range all {
		attr := ber.NewSequence("")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, value := range vs {
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
		}
		attr.AppendChild(values)
		attrs.AppendChild(attr)
	}
	op.AppendChild(attrs)
	return op
}

// noFactors is an MFA service whose accounts hold no second factor.
type noFactors struct{ auth.MFAEnroller }

func (noFactors) LoginFactors(context.Context, uuid.UUID) ([]auth.LoginFactor, error) {
	return nil, nil
}

// TestLapsedPlanStopsLDAPSignIn checks that a connection set up while the plan
// included LDAP signs no one in once the plan has lapsed.
func TestLapsedPlanStopsLDAPSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	const userDN = "uid=alice,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{"cn=service,dc=example,dc=test": "service-secret", userDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: userDN, attrs: map[string]string{"mail": a.Email, "cn": "Alice"}}},
	}
	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
		VALUES ($1, 'Directory', $2, 'cn=service,dc=example,dc=test', 'service-secret', 'dc=example,dc=test', 'active')
		RETURNING id
	`, tenant, dir.start(t)).Scan(&connID); err != nil {
		t.Fatalf("connection: %v", err)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := NewService(pool, authSvc, egress.DevelopmentPolicy())
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
	tenant := dbtest.Tenant(t)
	a := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+dbtest.Domain(t, tenant), tenant, tenant)
	const userDN = "uid=alice,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{"cn=service,dc=example,dc=test": "service-secret", userDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: userDN, attrs: map[string]string{"mail": a.Email, "cn": "Alice"}}},
	}
	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
		VALUES ($1, 'Directory', $2, 'cn=service,dc=example,dc=test', 'service-secret', 'dc=example,dc=test', 'active')
		RETURNING id
	`, tenant, dir.start(t)).Scan(&connID); err != nil {
		t.Fatalf("connection: %v", err)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := NewService(pool, authSvc, egress.DevelopmentPolicy())

	if _, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test"); !errors.Is(err, errs.ErrLDAPAccountUnverified) {
		t.Errorf("adopt an account whose address isn't verified: %v, want %v", err, errs.ErrLDAPAccountUnverified)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("verify the address: %v", err)
	}
	res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test")
	if err != nil || res.Pair == nil || res.Pair.UserID != a.ID || res.Pair.TenantID == nil || *res.Pair.TenantID != tenant {
		t.Fatalf("sign in: %+v, %v", res, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE "user".users SET mfa_required = TRUE WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("require MFA: %v", err)
	}
	res, err = svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test")
	if err != nil || res.Pair != nil || !res.MFARequired || res.MFAToken == "" {
		t.Errorf("sign in to an account that must use a second factor: %+v, %v; want a challenge", res, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET mfa_required = FALSE WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("lift MFA: %v", err)
	}

	for _, name := range []string{"alice", " alice", "ALICE", "alice  ", " Alice "} {
		if _, err := svc.Login(ctx, connID, name, "wrong", "192.0.2.20", "test"); !errors.Is(err, errs.ErrLDAPInvalidCredentials) {
			t.Fatalf("wrong password as %q: %v, want %v", name, err, errs.ErrLDAPInvalidCredentials)
		}
	}
	if _, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.20", "test"); !errors.Is(err, errs.ErrAuthAccountLocked) {
		t.Errorf("right password after five wrong ones: %v, want %v", err, errs.ErrAuthAccountLocked)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID); n != 1 {
		t.Errorf("%d sessions, want only the first sign-in's", n)
	}
}

// TestLoginSpeaksOnlyForTheOrganisation checks that a directory sign-in
// creates or adopts an account only on a domain the organisation has
// verified, adopts no administrator by address, that a DN linked through one
// connection signs nobody in through another, and that a draft connection
// signs nobody in.
func TestLoginSpeaksOnlyForTheOrganisation(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	domain := dbtest.Domain(t, tenant)
	admin := dbtest.UserAt(t, dbtest.Unique("root")+"@"+domain, tenant)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, admin.ID, tenant, dbtest.Role(t, tenant, "policy.write"))
	newcomer := dbtest.Unique("alice") + "@" + domain
	const service, aliceDN, bobDN, rootDN = "cn=service,dc=example,dc=test", "uid=alice,dc=example,dc=test", "uid=bob,dc=example,dc=test", "uid=root,dc=example,dc=test"
	binds := map[string]string{service: "service-secret", aliceDN: "alice-secret", bobDN: "bob-secret", rootDN: "root-secret"}
	connect := func(entries map[string]dirEntry) uuid.UUID {
		dir := &directory{binds: binds, entries: entries}
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `
			INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
			VALUES ($1, 'Directory', $2, $3, 'service-secret', 'dc=example,dc=test', 'active')
			RETURNING id
		`, tenant, dir.start(t), service).Scan(&id); err != nil {
			t.Fatalf("connection: %v", err)
		}
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
	svc := NewService(pool, authSvc, egress.DevelopmentPolicy())

	res, err := svc.Login(ctx, conn, "alice", "alice-secret", "192.0.2.21", "test")
	if err != nil || res.Pair == nil || dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND tenant_id = $2 AND email = $3`, res.Pair.UserID, tenant, newcomer) != 1 {
		t.Fatalf("a newcomer on the organisation's domain: %+v, %v; want an account in it", res, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1 AND connection_id = $2 AND subject = $3`, res.Pair.UserID, conn, aliceDN); n != 1 {
		t.Errorf("%d identities linked to the connection, want 1", n)
	}
	for _, c := range []struct {
		name     string
		conn     uuid.UUID
		username string
		want     error
	}{
		{"a newcomer on a domain nobody verified", conn, "bob", errs.ErrLDAPEmailDomainUnverified},
		{"an administrator's address", conn, "root", errs.ErrLDAPAccountAdministers},
		{"another connection's linked DN", rogue, "alice", errs.ErrLDAPEmailDomainUnverified},
	} {
		if _, err := svc.Login(ctx, c.conn, c.username, c.username+"-secret", "192.0.2.21", "test"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1`, admin.ID); n != 0 {
		t.Errorf("the administrator was linked to the directory")
	}

	if _, err := pool.Exec(ctx, `UPDATE tenant.ldap_connections SET status = 'draft' WHERE id = $1`, conn); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, conn, "alice", "alice-secret", "192.0.2.21", "test"); !errors.Is(err, errs.ErrLDAPConnectionDraft) {
		t.Errorf("a sign-in through a draft connection: %v, want %v", err, errs.ErrLDAPConnectionDraft)
	}
}

// TestLoginAdoptsADirectoryProvisionedAccount checks that an account the
// organisation's directory provisioned over SCIM, its address never proved,
// signs in through the organisation's LDAP connection.
func TestLoginAdoptsADirectoryProvisionedAccount(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	a := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+dbtest.Domain(t, tenant), tenant, tenant)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET provisioned_via = 'scim', email_verified_at = NULL WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	const userDN = "uid=alice,dc=example,dc=test"
	dir := &directory{
		binds:   map[string]string{"cn=service,dc=example,dc=test": "service-secret", userDN: "alice-secret"},
		entries: map[string]dirEntry{"alice": {dn: userDN, attrs: map[string]string{"mail": a.Email, "cn": "Alice"}}},
	}
	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
		VALUES ($1, 'Directory', $2, 'cn=service,dc=example,dc=test', 'service-secret', 'dc=example,dc=test', 'active')
		RETURNING id
	`, tenant, dir.start(t)).Scan(&connID); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	res, err := NewService(pool, authSvc, egress.DevelopmentPolicy()).Login(ctx, connID, "alice", "alice-secret", "192.0.2.22", "test")
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
	tenant := dbtest.Tenant(t)
	email := dbtest.Unique("alice") + "@" + dbtest.Domain(t, tenant)
	const service, userDN = "cn=service,dc=example,dc=test", "uid=alice,dc=example,dc=test"
	serve := func(entry dirEntry) string {
		dir := &directory{binds: map[string]string{service: "service-secret", userDN: "alice-secret"}, entries: map[string]dirEntry{"alice": entry}}
		return dir.start(t)
	}
	var connID, engineering uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
		VALUES ($1, 'Directory', $2, $3, 'service-secret', 'dc=example,dc=test', 'active')
		RETURNING id
	`, tenant, serve(dirEntry{dn: userDN, attrs: map[string]string{"mail": email, "cn": "Alice"},
		multi: map[string][]string{"memberOf": {"CN=Engineering,OU=Groups,DC=example,DC=test", "CN=Unmapped,OU=Groups,DC=example,DC=test"}}}),
		service).Scan(&connID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'Engineering') RETURNING id`, tenant).Scan(&engineering); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.sso_group_mappings (tenant_id, connection_id, idp_group, group_id) VALUES ($1, $2, 'cn=engineering,ou=groups,dc=example,dc=test', $3)`, tenant, connID, engineering); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := NewService(pool, authSvc, egress.DevelopmentPolicy())

	res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.23", "test")
	if err != nil || res.Pair == nil {
		t.Fatalf("sign in: %+v, %v", res, err)
	}
	alice := res.Pair.UserID
	synced := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM tenant.group_members WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3 AND source_connection_id = $4`,
			tenant, engineering, alice, connID)
	}
	if synced() != 1 {
		t.Fatal("the sign-in didn't put the person in the group their memberOf is mapped to")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'group.member_added' AND resource_id = $2 AND actor_type = 'ldap'`, tenant, engineering); n != 1 {
		t.Errorf("%d member_added events by the sign-in, want 1", n)
	}

	// The directory renames her and drops the group.
	if _, err := pool.Exec(ctx, `UPDATE tenant.ldap_connections SET server_url = $2 WHERE id = $1`, connID,
		serve(dirEntry{dn: userDN, attrs: map[string]string{"mail": email, "cn": "Alice Smith"}})); err != nil {
		t.Fatal(err)
	}
	if res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.23", "test"); err != nil || res.Pair == nil || res.Pair.UserID != alice {
		t.Fatalf("sign in again: %+v, %v; want the same person", res, err)
	}
	if synced() != 0 {
		t.Error("the person is still in the group the directory no longer lists")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND display_name = 'Alice Smith'`, alice); n != 1 {
		t.Error("the sign-in didn't refresh the display name from the directory")
	}
}

// TestLoginProvisionsOnlyWithJIT checks that a directory sign-in creates an
// account only while the organisation's domain has just-in-time provisioning
// on, and adopts an existing member's account either way.
func TestLoginProvisionsOnlyWithJIT(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	domain := dbtest.Domain(t, tenant)
	setJIT := func(on bool) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE tenant.domains SET jit_enabled = $2 WHERE tenant_id = $1`, tenant, on); err != nil {
			t.Fatal(err)
		}
	}
	setJIT(false)
	member := dbtest.UserAt(t, dbtest.Unique("alice")+"@"+domain, tenant, tenant)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, member.ID); err != nil {
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
	var connID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant.ldap_connections (tenant_id, name, server_url, bind_dn, bind_password, base_dn, status)
		VALUES ($1, 'Directory', $2, $3, 'service-secret', 'dc=example,dc=test', 'active')
		RETURNING id
	`, tenant, dir.start(t), service).Scan(&connID); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	svc := NewService(pool, authSvc, egress.DevelopmentPolicy())

	if res, err := svc.Login(ctx, connID, "alice", "alice-secret", "192.0.2.23", "test"); err != nil || res.Pair == nil || res.Pair.UserID != member.ID {
		t.Fatalf("adopt a member while the domain has JIT off: %+v, %v", res, err)
	}
	if _, err := svc.Login(ctx, connID, "bob", "bob-secret", "192.0.2.23", "test"); !errors.Is(err, errs.ErrLDAPJITNotAllowed) {
		t.Errorf("a newcomer while the domain has JIT off: %v, want %v", err, errs.ErrLDAPJITNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, newcomer); n != 0 {
		t.Fatal("a newcomer was provisioned while the domain has JIT off")
	}
	setJIT(true)
	res, err := svc.Login(ctx, connID, "bob", "bob-secret", "192.0.2.23", "test")
	if err != nil || res.Pair == nil || dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND tenant_id = $2 AND email = $3`, res.Pair.UserID, tenant, newcomer) != 1 {
		t.Errorf("a newcomer while the domain has JIT on: %+v, %v; want an account in the organisation", res, err)
	}
}

// TestLDAPTrustChangeMustOutrankLinkedAdministrators checks that pointing a
// directory connection an owner is linked to at another server, or at other
// entries of its directory, is refused to someone who can change connections
// but doesn't outrank the owner, as it could then sign in as them, while
// renaming it isn't.
func TestLDAPTrustChangeMustOutrankLinkedAdministrators(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	h := &Handler{Service: directoryService(t), ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, editor := dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant)
	dbtest.Assign(t, owner.ID, tenant, ownerRole)
	dbtest.Assign(t, editor.ID, tenant, dbtest.Role(t, tenant, "connection.write", "connection.read"))
	base := "/tenants/" + tenant.String() + "/ldap"
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(owner.ID, tenant), h.Mount), http.MethodPost, base, map[string]any{
		"name": "Directory", "server_url": "ldap://directory.example.test", "bind_dn": "cn=service,dc=example,dc=test",
		"bind_password": "service-secret", "base_dn": "dc=example,dc=test", "status": "active",
	})
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := pool.Exec(ctx, `INSERT INTO "user".external_identities (user_id, tenant_id, provider, connection_id, subject) VALUES ($1, $2, 'ldap', $3, 'uid=owner')`,
		owner.ID, tenant, conn.ID); err != nil {
		t.Fatal(err)
	}
	asEditor := dbtest.Serve(dbtest.Principal(editor.ID, tenant), h.Mount)

	for name, body := range map[string]map[string]any{
		"server":      {"server_url": "ldap://directory.attacker.example"},
		"base DN":     {"base_dn": "ou=people,dc=example,dc=test"},
		"user filter": {"user_filter": "(mail=%s)"},
	} {
		if rec := dbtest.Do(t, asEditor, http.MethodPatch, base+"/"+conn.ID.String(), body); rec.Code != http.StatusForbidden ||
			!strings.Contains(rec.Body.String(), errs.CodeRBACTrustChangeOutranks) {
			t.Errorf("an editor changes the %s of a connection an owner is linked to: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), errs.CodeRBACTrustChangeOutranks)
		}
	}
	if rec := dbtest.Do(t, asEditor, http.MethodPatch, base+"/"+conn.ID.String(), map[string]any{"name": "Directory (EU)"}); rec.Code != http.StatusOK {
		t.Errorf("an editor renames it: %d %s, want 200", rec.Code, rec.Body.String())
	}
}
