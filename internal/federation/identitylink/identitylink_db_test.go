//go:build integration

package identitylink

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestAdministersCountsEveryPrivilegedPermission checks that every permission
// outside the member allowlist, held directly or through a group, makes an
// account an administrator, as does the owner role and a permission added
// after this release; holding every allowlisted permission doesn't.
func TestAdministersCountsEveryPrivilegedPermission(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	if err := rbac.NewRepository(pool).SeedBuiltins(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT key FROM rbac.permissions ORDER BY key`)
	if err != nil {
		t.Fatal(err)
	}
	var privileged []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(MemberPermissions(), key) {
			privileged = append(privileged, key)
		}
	}
	rows.Close()
	for _, key := range []string{"gdpr.write", "secret.read", "secret.write", "apikey.write", "billing.write", "audit.write", "branding.write"} {
		if !slices.Contains(privileged, key) {
			t.Fatalf("%s is not counted as administrative", key)
		}
	}
	privileged = append(privileged, dbtest.Unique("newfeature")+".manage")

	tenant := dbtest.Tenant(t)
	conn := uuid.New()
	linked := func(userID uuid.UUID) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO "user".external_identities (user_id, tenant_id, provider, connection_id, subject) VALUES ($1, $2, 'saml', $3, $4)`,
			userID, tenant, conn, dbtest.Unique("subject")); err != nil {
			t.Fatal(err)
		}
	}
	throughGroup := func(userID, role uuid.UUID) {
		t.Helper()
		var group uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id`, tenant, dbtest.Unique("group")).Scan(&group); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, tenant, group, role); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO tenant.group_members (tenant_id, group_id, user_id) VALUES ($1, $2, $3)`, tenant, group, userID); err != nil {
			t.Fatal(err)
		}
	}

	want := map[uuid.UUID]string{}
	for _, key := range privileged {
		role := dbtest.Role(t, tenant, key)
		direct, grouped := dbtest.User(t, tenant), dbtest.User(t, tenant)
		dbtest.Assign(t, direct.ID, tenant, role)
		throughGroup(grouped.ID, role)
		want[direct.ID], want[grouped.ID] = key+" directly", key+" through a group"
	}
	var owner uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', TRUE) RETURNING id`, tenant).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	ownerAccount := dbtest.User(t, tenant)
	dbtest.Assign(t, ownerAccount.ID, tenant, owner)
	want[ownerAccount.ID] = "the owner role"
	for id, what := range want {
		linked(id)
		ok, err := Administers(ctx, pool, id, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("an account holding %s is not an administrator", what)
		}
	}

	reader := dbtest.User(t, tenant)
	readerRole := dbtest.Role(t, tenant, MemberPermissions()...)
	dbtest.Assign(t, reader.ID, tenant, readerRole)
	groupReader := dbtest.User(t, tenant)
	throughGroup(groupReader.ID, readerRole)
	for _, id := range []uuid.UUID{reader.ID, groupReader.ID} {
		linked(id)
		ok, err := Administers(ctx, pool, id, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("an account holding only %v is an administrator", MemberPermissions())
		}
	}

	admins, err := LinkedAdministrators(ctx, pool, tenant, conn, "saml")
	if err != nil {
		t.Fatal(err)
	}
	for id, what := range want {
		if !slices.Contains(admins, id) {
			t.Errorf("a linked account holding %s is not among the linked administrators", what)
		}
	}
	if len(admins) != len(want) {
		t.Errorf("%d linked administrators, want %d: the allowlisted readers are not administrators", len(admins), len(want))
	}
}
