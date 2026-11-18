//go:build integration

package ssosync

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	scimdb "github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/group"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// fixture is an organization with groups, a person and helpers to sign them
// in through a connection.
type fixture struct {
	t            *testing.T
	organization uuid.UUID
	domain       string
	person       dbtest.Account
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	return &fixture{t: t, organization: organization, domain: domain, person: dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization)}
}

// group creates one of the organization's groups holding roles.
func (f *fixture) group(name string, roles ...uuid.UUID) uuid.UUID {
	f.t.Helper()
	return makeGroup(f.t, f.organization, name, "", roles...)
}

// makeGroup creates a group of organization holding roles; a non-empty externalID
// makes it a group SCIM provisioned.
func makeGroup(t *testing.T, organization uuid.UUID, name, externalID string, roles ...uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var ext, via any
	if externalID != "" {
		ext, via = externalID, "scim"
	}
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `
		INSERT INTO organization.groups (organization_id, name, external_id, provisioned_via) VALUES ($1, $2, $3, $4) RETURNING id
	`, organization, name+"-"+uuid.NewString()[:8], ext, via).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, id, role); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// ownerRole creates organization's owner role.
func ownerRole(t *testing.T, organization uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(context.Background(), `
		INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id
	`, organization).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// mapGroup maps idpGroup to groupID for connection, bypassing the API's checks.
func mapGroup(t *testing.T, organization, connection uuid.UUID, idpGroup string, groupID uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(context.Background(), `
		INSERT INTO organization.sso_group_mappings (organization_id, connection_id, idp_group, group_id) VALUES ($1, $2, $3, $4)
	`, organization, connection, idpGroup, groupID); err != nil {
		t.Fatal(err)
	}
}

// signIn applies a sign-in of the person through connection in its own
// transaction, as SAML and LDAP sign-in do.
func (f *fixture) signIn(connection uuid.UUID, in SignIn) {
	f.t.Helper()
	ctx := dbtest.Context(f.t)
	in.OrganizationID, in.UserID, in.ConnectionID = f.organization, f.person.ID, connection
	if in.Provider == "" {
		in.Provider = "saml"
	}
	in.Actor = audit.Actor{Type: in.Provider, IP: "192.0.2.10", UserAgent: "test"}
	tx, err := dbtest.Pool(f.t).Begin(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := Apply(ctx, tx, in); err != nil {
		f.t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		f.t.Fatal(err)
	}
}

// memberships returns the person's groups, each with the connection that made
// it (uuid.Nil: an administrator, an import or SCIM).
func (f *fixture) memberships() map[uuid.UUID]uuid.UUID {
	f.t.Helper()
	rows, err := dbtest.Pool(f.t).Query(context.Background(), `
		SELECT group_id, COALESCE(source_connection_id, '00000000-0000-0000-0000-000000000000') FROM organization.group_members WHERE organization_id = $1 AND user_id = $2
	`, f.organization, f.person.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]uuid.UUID{}
	for rows.Next() {
		var g, source uuid.UUID
		if err := rows.Scan(&g, &source); err != nil {
			f.t.Fatal(err)
		}
		out[g] = source
	}
	return out
}

// audited counts the organization's audit events of action on resource by actorType.
func audited(t *testing.T, organization uuid.UUID, action string, resource uuid.UUID, actorType string) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3 AND actor_type = $4`,
		organization, action, resource, actorType)
}

// TestSignInSyncsGroups checks that a sign-in puts the person in the groups
// its asserted groups reach, by the connection's mappings or a SCIM group's
// external id and ignoring case, and later takes them out of only those it put
// them in: never a membership an administrator, SCIM or another connection
// made, and never into a group granting the owner role or an administrative
// permission. Withheld groups change nothing.
func TestSignInSyncsGroups(t *testing.T) {
	f := newFixture(t)
	conn, other := uuid.New(), uuid.New()
	engineering := f.group("Engineering")
	directory := makeGroup(t, f.organization, "Directory", "00g-ext-1")
	design := f.group("Design")
	admins := f.group("Admins", dbtest.Role(t, f.organization, "role.write", "user.read"))
	owners := f.group("Owners", ownerRole(t, f.organization))
	privacy := f.group("Privacy", dbtest.Role(t, f.organization, "gdpr.write"))
	elsewhere := f.group("Elsewhere")
	mapGroup(t, f.organization, conn, "Engineering", engineering)
	mapGroup(t, f.organization, conn, "Design", design)
	mapGroup(t, f.organization, conn, "Admins", admins)
	mapGroup(t, f.organization, conn, "Owners", owners)
	mapGroup(t, f.organization, conn, "Privacy", privacy)
	mapGroup(t, f.organization, other, "Elsewhere", elsewhere)
	// An administrator already put the person in Design.
	if err := groups(t).AddMember(context.Background(), design, f.person.ID, f.organization, audit.Actor{Type: "user"}); err != nil {
		t.Fatal(err)
	}
	f.signIn(other, SignIn{Groups: []string{"Elsewhere"}})

	f.signIn(conn, SignIn{Groups: []string{"engineering", "00G-EXT-1", "Design", "Admins", "Owners", "Privacy", "Unmapped"}})
	got := f.memberships()
	want := map[uuid.UUID]uuid.UUID{engineering: conn, directory: conn, design: uuid.Nil, elsewhere: other}
	if len(got) != len(want) {
		t.Fatalf("memberships %v, want %v", got, want)
	}
	for g, source := range want {
		if got[g] != source {
			t.Errorf("group %s made by %s, want %s", g, got[g], source)
		}
	}
	for _, g := range []uuid.UUID{engineering, directory} {
		if n := audited(t, f.organization, "group.member_added", g, "saml"); n != 1 {
			t.Errorf("%d member_added events for group %s by the sign-in, want 1", n, g)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'group.member_added'`, engineering); n != 1 {
		t.Errorf("%d member_added events published for Engineering, want 1", n)
	}

	// Signing in again with the same groups changes nothing.
	f.signIn(conn, SignIn{Groups: []string{"Engineering", "00g-ext-1"}})
	if n := audited(t, f.organization, "group.member_added", engineering, "saml"); n != 1 {
		t.Errorf("%d member_added events for Engineering after a second sign-in, want 1", n)
	}

	// The IdP withholds the groups: nothing changes.
	f.signIn(conn, SignIn{GroupsWithheld: true})
	if got := f.memberships(); len(got) != 4 {
		t.Errorf("memberships after withheld groups: %v, want the four kept", got)
	}

	// The IdP stops asserting them: only the connection's go.
	f.signIn(conn, SignIn{})
	got = f.memberships()
	if _, ok := got[engineering]; ok {
		t.Error("still in Engineering after the IdP stopped asserting it")
	}
	if _, ok := got[directory]; ok {
		t.Error("still in the SCIM group after the IdP stopped asserting it")
	}
	if got[design] != uuid.Nil || got[elsewhere] != other || len(got) != 2 {
		t.Errorf("memberships %v; want the administrator's Design and the other connection's kept", got)
	}
	if n := audited(t, f.organization, "group.member_removed", engineering, "saml"); n != 1 {
		t.Errorf("%d member_removed events for Engineering, want 1", n)
	}

	// A group that comes to grant administrative authority loses the members
	// sign-in put in it.
	f.signIn(conn, SignIn{Groups: []string{"Engineering"}})
	if _, err := dbtest.Pool(t).Exec(context.Background(), `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`,
		f.organization, engineering, dbtest.Role(t, f.organization, "connection.write")); err != nil {
		t.Fatal(err)
	}
	f.signIn(conn, SignIn{Groups: []string{"Engineering"}})
	if _, ok := f.memberships()[engineering]; ok {
		t.Error("sign-in kept the person in a group granting connection.write")
	}
}

// TestMembershipsMadeByOthersStay checks that an administrator or SCIM adding
// someone a sign-in put in a group makes the membership theirs, so sign-in no
// longer removes it.
func TestMembershipsMadeByOthersStay(t *testing.T) {
	f := newFixture(t)
	conn := uuid.New()
	byAdmin, byDirectory := f.group("Payments"), makeGroup(t, f.organization, "Support", "00g-support")
	mapGroup(t, f.organization, conn, "Payments", byAdmin)
	f.signIn(conn, SignIn{Groups: []string{"Payments", "00g-support"}})
	if got := f.memberships(); got[byAdmin] != conn || got[byDirectory] != conn {
		t.Fatalf("memberships %v, want both made by the sign-in", got)
	}
	if err := groups(t).AddMember(context.Background(), byAdmin, f.person.ID, f.organization, audit.Actor{Type: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := scimdb.New(dbtest.Pool(t)).AddGroupMember(context.Background(), scimdb.AddGroupMemberParams{GroupID: byDirectory, UserID: f.person.ID, OrganizationID: f.organization}); err != nil {
		t.Fatal(err)
	}
	f.signIn(conn, SignIn{})
	if got := f.memberships(); len(got) != 2 || got[byAdmin] != uuid.Nil || got[byDirectory] != uuid.Nil {
		t.Errorf("memberships %v, want both kept as the administrator's and the directory's", got)
	}
}

// TestSignInSyncStaysInItsOrganization checks that a sign-in reaches only its
// own organization's mappings and SCIM groups, whatever the other
// organization names them.
func TestSignInSyncStaysInItsOrganization(t *testing.T) {
	f := newFixture(t)
	conn := uuid.New()
	theirs := dbtest.Organization(t)
	theirGroup := makeGroup(t, theirs, "Engineering", "00g-shared")
	// Their mapping names this connection, as if it were theirs.
	mapGroup(t, theirs, conn, "Engineering", theirGroup)
	f.signIn(conn, SignIn{Groups: []string{"Engineering", "00g-shared"}})
	if got := f.memberships(); len(got) != 0 {
		t.Errorf("memberships %v, want none", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE group_id = $1`, theirGroup); n != 0 {
		t.Errorf("another organization's group gained %d members", n)
	}
}

// TestSignInRefreshesProfile checks that a sign-in sets the asserted display
// name, and moves the account to the asserted address only on a domain the
// organization manages, when no other account holds it and the account doesn't
// administer the organization, ending the links sent to the old address.
func TestSignInRefreshesProfile(t *testing.T) {
	f := newFixture(t)
	conn := uuid.New()
	ctx := context.Background()
	pool := dbtest.Pool(t)
	profile := func() (string, string, bool) {
		t.Helper()
		var email, name string
		var verified bool
		if err := pool.QueryRow(ctx, `SELECT email, COALESCE(display_name, ''), email_verified_at IS NOT NULL FROM account.users WHERE id = $1`, f.person.ID).Scan(&email, &name, &verified); err != nil {
			t.Fatal(err)
		}
		return email, name, verified
	}

	f.signIn(conn, SignIn{DisplayName: "  Asha Rao  ", Email: f.person.Email, EmailManaged: true})
	if _, name, _ := profile(); name != "Asha Rao" {
		t.Errorf("display name %q, want the asserted one", name)
	}
	if n := audited(t, f.organization, "user.updated", f.person.ID, "saml"); n != 1 {
		t.Errorf("%d user.updated events, want 1", n)
	}
	f.signIn(conn, SignIn{DisplayName: "Asha Rao"})
	if n := audited(t, f.organization, "user.updated", f.person.ID, "saml"); n != 1 {
		t.Errorf("%d user.updated events after an unchanged sign-in, want 1", n)
	}

	// An address off the organization's domains is not taken.
	f.signIn(conn, SignIn{Email: dbtest.Unique("asha") + "@example.test", EmailManaged: false})
	if email, _, _ := profile(); email != f.person.Email {
		t.Errorf("address moved to %q off the organization's domains", email)
	}

	// Another account's address is not taken, and the sign-in still applies.
	taken := dbtest.UserAt(t, dbtest.Unique("taken")+"@"+f.domain, f.organization)
	f.signIn(conn, SignIn{Email: taken.Email, EmailManaged: true, DisplayName: "Asha R."})
	if email, name, _ := profile(); email != f.person.Email || name != "Asha R." {
		t.Errorf("profile %q %q; want the address kept and the name changed", email, name)
	}

	// A new address on the organization's domain is taken, verified, and the
	// links sent to the old one stop working.
	if _, err := pool.Exec(ctx, `INSERT INTO auth.password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')`, f.person.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth.magic_links (organization_id, email, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')`, f.organization, f.person.Email, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	moved := dbtest.Unique("asha.rao") + "@" + f.domain
	f.signIn(conn, SignIn{Email: moved, EmailManaged: true})
	if email, _, verified := profile(); email != moved || !verified {
		t.Errorf("address %q (verified %v), want %q verified", email, verified, moved)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.password_resets WHERE user_id = $1 AND expires_at > NOW()`, f.person.ID); n != 0 {
		t.Errorf("%d reset links still open after the address changed", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.magic_links WHERE lower(email) = lower($1) AND expires_at > NOW()`, f.person.Email); n != 0 {
		t.Errorf("%d sign-in links to the old address still open", n)
	}

	// An account that administers the organization keeps its address.
	dbtest.Assign(t, f.person.ID, f.organization, dbtest.Role(t, f.organization, "user.write"))
	f.signIn(conn, SignIn{Email: dbtest.Unique("admin") + "@" + f.domain, EmailManaged: true})
	if email, _, _ := profile(); email != moved {
		t.Errorf("an administrator's address moved to %q", email)
	}
}

// groups is the group service, its membership not capped by seats.
func groups(t *testing.T) *group.Service {
	t.Helper()
	svc, err := group.NewService(dbtest.Pool(t), noSeatLimit{})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// noSeatLimit leaves group membership uncapped.
type noSeatLimit struct{}

func (noSeatLimit) SeatLimit(context.Context, uuid.UUID) (int, error) { return -1, nil }

func (noSeatLimit) WithinSeats(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ int, change func() error) error {
	return change()
}
