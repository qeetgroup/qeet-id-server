//go:build integration

package user

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestUsersStayInTheirOrganization checks that an administrator of one organization can
// neither read nor change a user who belongs only to another organization.
func TestUsersStayInTheirOrganization(t *testing.T) {
	pool := dbtest.Pool(t)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	victim := dbtest.User(t, organizationA, organizationA)
	adminA := dbtest.User(t, organizationA, organizationA)
	adminB := dbtest.User(t, organizationB, organizationB)

	h := &Handler{
		Repo:           NewRepository(pool),
		Validate:       validator.New(validator.WithRequiredStructEnabled()),
		PasswordPolicy: func(context.Context, uuid.UUID, string, string) error { return nil },
		SignIns:        endSessions{},
		Mailer:         &dbtest.Mailbox{},
		ActOnCheck:     rbac.NewRepository(pool).CheckActOn,
	}
	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), h.Mount)
	path := "/users/" + victim.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, path, nil},
		{http.MethodGet, path + "/security", nil},
		{http.MethodGet, path + "/access", nil},
		{http.MethodPatch, path, map[string]any{"display_name": "changed"}},
		{http.MethodPatch, path, map[string]any{"status": "suspended"}},
		{http.MethodPost, path + "/password", map[string]any{"password": "Kx7mQ2vLp9Wz-other"}},
		{http.MethodPut, path + "/mfa-required", map[string]any{"required": true}},
		{http.MethodDelete, path + "/membership", nil},
		{http.MethodDelete, path, nil},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != http.StatusNotFound {
			t.Errorf("organization B %s %s: status %d, want 404 (%s)", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/users", nil)); slices.Contains(ids, victim.ID) {
		t.Error("organization B's user list includes organization A's user")
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM account.users
		WHERE id = $1 AND status = 'active' AND deleted_at IS NULL AND display_name IS NULL
	`, victim.ID); n != 1 {
		t.Error("organization B changed organization A's user")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.password_credentials WHERE user_id = $1`, victim.ID); n != 0 {
		t.Error("organization B set a password for organization A's user")
	}

	asA := dbtest.Serve(dbtest.Principal(adminA.ID, organizationA), h.Mount)
	if rec := dbtest.Do(t, asA, http.MethodGet, path, nil); rec.Code != http.StatusOK {
		t.Fatalf("organization A reads its own user: status %d", rec.Code)
	}
}

// TestCreateUserInTheCallersOrganization checks that an administrator creates
// a person at home in their own organization whatever the body names, with the
// password hashed and the creation audited, and that a taken email, a refused
// password or a bad address leaves no account behind.
func TestCreateUserInTheCallersOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	otherAdmin := dbtest.User(t, other, other)
	h := testHandler(t, nil)
	h.PasswordPolicy = func(_ context.Context, _ uuid.UUID, _, plain string) error {
		if plain == "NoSymbolPassword99" {
			return errs.ErrAuthPolicyPasswordNoSymbol
		}
		return nil
	}
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	email := dbtest.Unique("new") + "@example.test"
	const plain = "Kx7mQ2vLp9Wz-new"

	rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"organization_id": other, "email": email, "password": plain, "display_name": "New Person"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create a user: status %d (%s)", rec.Code, rec.Body.String())
	}
	var created User
	dbtest.Decode(t, rec, &created)
	if created.OrganizationID != organization || created.Email != email || created.DisplayName == nil || *created.DisplayName != "New Person" || created.Status != "active" {
		t.Errorf("created %+v, want an active %s at home in the caller's organization", created, email)
	}
	var hash string
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id = $1`, created.ID).Scan(&hash); err != nil || !password.Verify(hash, plain) {
		t.Errorf("the new user's password isn't stored as a hash of the one given (%v)", err)
	}
	if n := audited(t, organization, "user.created", created.ID); n != 1 {
		t.Errorf("%d user.created audit events, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'user.created'`, created.ID); n != 1 {
		t.Errorf("%d user.created events, want 1", n)
	}

	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	for _, tc := range []struct {
		name string
		as   http.Handler
		body map[string]any
		want string
	}{
		{"the same email in capitals", as, map[string]any{"email": strings.ToUpper(email)}, errs.CodeAuthEmailExists},
		{"the same email from another organization", asOther, map[string]any{"email": email}, errs.CodeAuthEmailExists},
	} {
		rec := dbtest.Do(t, tc.as, http.MethodPost, "/users", tc.body)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("create with %s: %d %s, want 409 %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE lower(email) = lower($1)`, email); n != 1 {
		t.Errorf("%d accounts hold %s, want 1", n, email)
	}

	refused := dbtest.Unique("refused") + "@example.test"
	if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": refused, "password": "NoSymbolPassword99"}); !strings.Contains(rec.Body.String(), errs.CodeAuthPolicyPasswordNoSymbol) {
		t.Errorf("create with a refused password: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeAuthPolicyPasswordNoSymbol)
	}
	if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": "not-an-email"}); !strings.Contains(rec.Body.String(), errs.CodeValidation) {
		t.Errorf("create with a bad address: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
	h.PasswordPolicy = nil
	if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": refused, "password": plain}); rec.Code != http.StatusNotImplemented {
		t.Errorf("create with a password and no policy to check it: %d, want 501", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email IN ($1, 'not-an-email')`, refused); n != 0 {
		t.Errorf("refused creations left %d accounts", n)
	}
}

// TestCreatedUserIsListed checks that a person created in an organization
// appears in its user list and member counts, as they do in its other views.
func TestCreatedUserIsListed(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": dbtest.Unique("listed") + "@example.test"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create a user: status %d (%s)", rec.Code, rec.Body.String())
	}
	var created User
	dbtest.Decode(t, rec, &created)
	if rec := dbtest.Do(t, as, http.MethodGet, "/users/"+created.ID.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("read the new user: status %d", rec.Code)
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, as, http.MethodGet, "/users", nil)); !slices.Contains(ids, created.ID) {
		t.Error("the organization's user list leaves out the user it just created")
	}
	var stats UserStats
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users/stats", nil), &stats)
	if stats.Total != 2 {
		t.Errorf("the organization counts %d users, want 2", stats.Total)
	}
}

// TestPeopleEditOnlyTheirOwnProfile checks that /me reads and changes the
// caller's own account, keeps other metadata when setting the locale, and
// ignores fields that would change the person's standing.
func TestPeopleEditOnlyTheirOwnProfile(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	me := dbtest.User(t, organization, organization)
	exec(t, `UPDATE account.users SET metadata = '{"team":"blue"}' WHERE id = $1`, me.ID)
	as := dbtest.Serve(dbtest.Principal(me.ID, organization), testHandler(t, nil).Mount)

	var got User
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/me", nil), &got)
	if got.ID != me.ID || got.Email != me.Email {
		t.Fatalf("/me is %+v, want %s", got, me.Email)
	}
	rec := dbtest.Do(t, as, http.MethodPatch, "/me", map[string]any{
		"display_name": "Me", "locale": "fr", "status": "suspended", "phone": "+14155550100", "metadata": map[string]any{"admin": true},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update /me: status %d (%s)", rec.Code, rec.Body.String())
	}
	var status, name, locale, team string
	var phone *string
	var admin *bool
	if err := dbtest.Pool(t).QueryRow(ctx, `
		SELECT status, display_name, phone, metadata->>'locale', metadata->>'team', (metadata->>'admin')::boolean
		FROM account.users WHERE id = $1
	`, me.ID).Scan(&status, &name, &phone, &locale, &team, &admin); err != nil {
		t.Fatal(err)
	}
	if status != "active" || phone != nil || admin != nil {
		t.Errorf("/me changed the person's standing: status %s, phone %v, admin metadata %v", status, phone, admin)
	}
	if name != "Me" || locale != "fr" || team != "blue" {
		t.Errorf("/me profile is %q, locale %q, team %q; want Me, fr and the team kept", name, locale, team)
	}
	if rec := dbtest.Do(t, as, http.MethodPatch, "/me", map[string]any{"locale": "xx"}); !strings.Contains(rec.Body.String(), errs.CodeValidation) {
		t.Errorf("set an unknown locale: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
	if rec := dbtest.Do(t, as, http.MethodPatch, "/me", map[string]any{"avatar_url": "https://example.test/me.png"}); !strings.Contains(rec.Body.String(), errs.CodeValidation) {
		t.Errorf("set an avatar that isn't an image data URL: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
}

// TestAdminProfileEditsAreAudited checks that an administrator's edit of a
// person's profile is recorded as user.updated naming the fields it changed,
// never their values; that an edit changing nothing records nothing; and that
// a suspension made in the same edit keeps its own record.
func TestAdminProfileEditsAreAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	target := dbtest.User(t, organization, organization)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	path := "/users/" + target.ID.String()
	edits := func() [][]string {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata->'changed' FROM audit.events
			WHERE organization_id = $1 AND action = 'user.updated' AND resource_id = $2 AND actor_user_id = $3
			ORDER BY created_at`, organization, target.ID, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out [][]string
		for rows.Next() {
			var changed []string
			if err := rows.Scan(&changed); err != nil {
				t.Fatal(err)
			}
			out = append(out, changed)
		}
		return out
	}
	patch := func(body map[string]any) {
		t.Helper()
		if rec := dbtest.Do(t, as, http.MethodPatch, path, body); rec.Code != http.StatusOK {
			t.Fatalf("update %v: %d %s", body, rec.Code, rec.Body.String())
		}
	}

	patch(map[string]any{"display_name": "Pat", "phone": "+14155550177", "metadata": map[string]any{"team": "red"}})
	if got, want := edits(), [][]string{{"display_name", "phone", "metadata"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("recorded %v, want %v", got, want)
	}
	patch(map[string]any{"display_name": "Pat", "phone": "+14155550177"})
	if got := edits(); len(got) != 1 {
		t.Errorf("an edit changing nothing was recorded: %v", got)
	}
	patch(map[string]any{"status": "suspended", "display_name": "Pat Lee"})
	if got := edits(); len(got) != 2 || !slices.Equal(got[1], []string{"display_name"}) {
		t.Errorf("recorded %v, want a second naming only the display name", got)
	}
	if n := audited(t, organization, "user.suspended", target.ID); n != 1 {
		t.Errorf("%d user.suspended records, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE resource_id = $1 AND strpos(metadata::text, '4155550177') > 0`, target.ID); n != 0 {
		t.Errorf("%d audit records hold the phone number", n)
	}
}

// TestAvatarCanBeCleared checks that an empty avatar_url removes the avatar, as
// UpdateInput documents.
func TestAvatarCanBeCleared(t *testing.T) {
	organization := dbtest.Organization(t)
	me := dbtest.User(t, organization, organization)
	as := dbtest.Serve(dbtest.Principal(me.ID, organization), testHandler(t, nil).Mount)
	if rec := dbtest.Do(t, as, http.MethodPatch, "/me", map[string]any{"avatar_url": "data:image/png;base64,AAAA"}); rec.Code != http.StatusOK {
		t.Fatalf("set an avatar: status %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as, http.MethodPatch, "/me", map[string]any{"avatar_url": ""}); rec.Code != http.StatusOK {
		t.Fatalf("clear the avatar: status %d (%s)", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND COALESCE(avatar_url, '') = ''`, me.ID); n != 1 {
		t.Error("the avatar is still set after clearing it")
	}
}

// TestDeleteRestoreAndPurge checks the recycle bin: a deletion records who did
// it and ends the person's sessions, restoring brings back the account but no
// session, a purge removes only a deleted account, and another organization
// can do none of it.
func TestDeleteRestoreAndPurge(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	otherAdmin := dbtest.User(t, other, other)
	target := dbtest.User(t, organization, organization)
	dbtest.SetPassword(t, target.ID, "Kx7mQ2vLp9Wz")
	session(t, target.ID, organization, "")
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	path := "/users/" + target.ID.String()

	rec := dbtest.Do(t, as, http.MethodDelete, path, nil)
	var d Deletion
	dbtest.Decode(t, rec, &d)
	if rec.Code != http.StatusOK || d.ID != target.ID || d.DeletedBy == nil || *d.DeletedBy != admin.ID || d.DeletedAt.IsZero() {
		t.Fatalf("delete: %d %+v, want the deletion recorded as the administrator's", rec.Code, d)
	}
	if n := liveSessions(t, target.ID); n != 0 {
		t.Errorf("%d sessions are still live after the deletion", n)
	}
	if n := audited(t, organization, "user.deleted", target.ID); n != 1 {
		t.Errorf("%d user.deleted audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("read a deleted user: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("delete twice: %d, want 404", rec.Code)
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, as, http.MethodGet, "/users/deleted", nil)); !slices.Contains(ids, target.ID) {
		t.Error("the recycle bin leaves out the deleted user")
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asOther, http.MethodGet, "/users/deleted", nil)); slices.Contains(ids, target.ID) {
		t.Error("another organization's recycle bin shows the deleted user")
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, path + "/restore"},
		{http.MethodDelete, path + "/purge"},
	} {
		if rec := dbtest.Do(t, asOther, tc.method, tc.path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("another organization %s %s: %d, want 404", tc.method, tc.path, rec.Code)
		}
	}

	rec = dbtest.Do(t, as, http.MethodPost, path+"/restore", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body.String())
	}
	if n := liveSessions(t, target.ID); n != 0 {
		t.Errorf("restoring the account brought back %d sessions", n)
	}
	if n := audited(t, organization, "user.restored", target.ID); n != 1 {
		t.Errorf("%d user.restored audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodPost, path+"/restore", nil); rec.Code != http.StatusNotFound {
		t.Errorf("restore a live account: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path+"/purge", nil); rec.Code != http.StatusNotFound {
		t.Errorf("purge a live account: %d, want 404", rec.Code)
	}

	if rec := dbtest.Do(t, as, http.MethodDelete, path, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete again: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path+"/purge", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("purge: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT (SELECT count(*) FROM account.users WHERE id = $1) + (SELECT count(*) FROM auth.password_credentials WHERE user_id = $1)`, target.ID); n != 0 {
		t.Error("the purge left the account or its password behind")
	}
	if n := audited(t, organization, "user.purged", target.ID); n != 1 {
		t.Errorf("%d user.purged audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodPost, path+"/restore", nil); rec.Code != http.StatusNotFound {
		t.Errorf("restore a purged account: %d, want 404", rec.Code)
	}
}

// TestRestoreWithATakenEmail checks that restoring an account whose email a
// newer account has taken meanwhile is refused as a conflict.
func TestRestoreWithATakenEmail(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	target := dbtest.User(t, organization, organization)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	if rec := dbtest.Do(t, as, http.MethodDelete, "/users/"+target.ID.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": target.Email}); rec.Code != http.StatusCreated {
		t.Fatalf("create a new account with the deleted one's email: %d %s", rec.Code, rec.Body.String())
	}
	rec := dbtest.Do(t, as, http.MethodPost, "/users/"+target.ID.String()+"/restore", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeAuthEmailExists) {
		t.Errorf("restore an account whose email is taken: %d %s, want 409 %s", rec.Code, rec.Body.String(), errs.CodeAuthEmailExists)
	}
	if n := audited(t, organization, "user.restored", target.ID); n != 0 {
		t.Errorf("a refused restore was recorded %d times", n)
	}
}

// TestRecycleBinActionsAreTheAdministrators checks that a restore and a purge
// are recorded as the administrator's, with where they came from.
func TestRecycleBinActionsAreTheAdministrators(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	target := dbtest.User(t, organization, organization)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	path := "/users/" + target.ID.String()
	byAdmin := func(action string) int {
		return dbtest.Count(t, `
			SELECT count(*) FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND resource_id = $3 AND actor_user_id = $4 AND actor_type = 'user'
			  AND user_agent IS NOT NULL`, organization, action, target.ID, admin.ID)
	}
	for _, step := range []struct{ method, path, action string }{
		{http.MethodDelete, path, "user.deleted"},
		{http.MethodPost, path + "/restore", "user.restored"},
		{http.MethodDelete, path, "user.deleted"},
		{http.MethodDelete, path + "/purge", "user.purged"},
	} {
		if rec := dbtest.Do(t, as, step.method, step.path, nil); rec.Code >= 300 {
			t.Fatalf("%s %s: %d %s", step.method, step.path, rec.Code, rec.Body.String())
		}
	}
	if byAdmin("user.restored") != 1 || byAdmin("user.purged") != 1 {
		t.Errorf("restore recorded %d, purge %d times as the administrator's; want once each", byAdmin("user.restored"), byAdmin("user.purged"))
	}
}

// TestRemovingAMemberLeavesTheirHomeAlone checks that an organization removing
// a member from elsewhere takes away their roles, groups, sessions, grants and
// API keys there and nothing in their home organization, which can't remove
// them this way.
func TestRemovingAMemberLeavesTheirHomeAlone(t *testing.T) {
	home, organization := dbtest.Organization(t), dbtest.Organization(t)
	homeAdmin := dbtest.User(t, home, home)
	admin := dbtest.User(t, organization, organization)
	member := dbtest.User(t, home, home, organization)
	for _, in := range []uuid.UUID{home, organization} {
		session(t, member.ID, in, "")
		exec(t, `
			WITH g AS (INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id)
			INSERT INTO organization.group_members (group_id, user_id, organization_id) SELECT id, $3, $1 FROM g
		`, in, dbtest.Unique("group"), member.ID)
		exec(t, `INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at)
			VALUES (gen_random_uuid()::text, 'test-app', $1, $2, NOW() + INTERVAL '1 day')`, member.ID, in)
		exec(t, `INSERT INTO auth.api_keys (organization_id, user_id, name, prefix, key_hash) VALUES ($1, $2, 'key', 'prefix00', 'hash')`, in, member.ID)
	}
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	path := "/users/" + member.ID.String() + "/membership"

	rec := dbtest.Do(t, as, http.MethodDelete, path, nil)
	var removal Removal
	dbtest.Decode(t, rec, &removal)
	if rec.Code != http.StatusOK || removal != (Removal{ID: member.ID, RolesRemoved: 1, SessionsEnded: 1}) {
		t.Fatalf("remove the member: %d %+v, want 1 role and 1 session", rec.Code, removal)
	}
	for _, left := range []struct{ what, sql string }{
		{"roles", `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`},
		{"groups", `SELECT count(*) FROM organization.group_members WHERE user_id = $1 AND organization_id = $2`},
		{"sessions", `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND organization_id = $2 AND revoked_at IS NULL`},
		{"application grants", `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND organization_id = $2 AND revoked_at IS NULL`},
		{"API keys", `SELECT count(*) FROM auth.api_keys WHERE user_id = $1 AND organization_id = $2 AND revoked_at IS NULL`},
	} {
		if n := dbtest.Count(t, left.sql, member.ID, organization); n != 0 {
			t.Errorf("%d %s are left in the organization the member was removed from", n, left.what)
		}
		if n := dbtest.Count(t, left.sql, member.ID, home); n != 1 {
			t.Errorf("removing the member elsewhere left %d %s in their home organization, want 1", n, left.what)
		}
	}
	if n := audited(t, organization, "user.removed_from_organization", member.ID); n != 1 {
		t.Errorf("%d user.removed_from_organization audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/users/"+member.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("read a removed member: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("remove the member twice: %d, want 404", rec.Code)
	}

	asHome := dbtest.Serve(dbtest.Principal(homeAdmin.ID, home), h.Mount)
	if rec := dbtest.Do(t, asHome, http.MethodDelete, path, nil); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), CodeManagedHere) {
		t.Errorf("the home organization removing its own account: %d %s, want 409 %s", rec.Code, rec.Body.String(), CodeManagedHere)
	}
}

// TestMemberFromElsewhereIsReadOnly checks that an organization can read a
// member whose account another organization manages, but can't change, suspend,
// delete or sign them out, set their password or touch their second factors.
func TestMemberFromElsewhereIsReadOnly(t *testing.T) {
	home, organization := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	member := dbtest.User(t, home, home, organization)
	session(t, member.ID, home, "")
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	path := "/users/" + member.ID.String()

	for _, read := range []string{path, path + "/security", path + "/sessions", path + "/access"} {
		if rec := dbtest.Do(t, as, http.MethodGet, read, nil); rec.Code != http.StatusOK {
			t.Errorf("read %s of a member from elsewhere: %d, want 200", read, rec.Code)
		}
	}
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPatch, path, map[string]any{"display_name": "changed"}},
		{http.MethodPatch, path, map[string]any{"status": "suspended"}},
		{http.MethodPost, path + "/reactivate", nil},
		{http.MethodPut, path + "/suspension", map[string]any{"reason": "other", "risk": "low", "review": "reviewed"}},
		{http.MethodDelete, path, nil},
		{http.MethodPost, path + "/restore", nil},
		{http.MethodDelete, path + "/purge", nil},
		{http.MethodPost, path + "/password", map[string]any{"password": "Kx7mQ2vLp9Wz-other"}},
		{http.MethodDelete, path + "/mfa", nil},
		{http.MethodPost, path + "/sessions/revoke-all", nil},
		{http.MethodPut, path + "/mfa-required", map[string]any{"required": true}},
	} {
		rec := dbtest.Do(t, as, tc.method, tc.path, tc.body)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeUserManagedElsewhere) {
			t.Errorf("another organization %s %s: %d %s, want 403 %s", tc.method, tc.path, rec.Code, rec.Body.String(), errs.CodeUserManagedElsewhere)
		}
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM account.users
		WHERE id = $1 AND status = 'active' AND deleted_at IS NULL AND display_name IS NULL AND NOT mfa_required
	`, member.ID); n != 1 {
		t.Error("another organization changed the member's account")
	}
	if n := liveSessions(t, member.ID); n != 1 {
		t.Errorf("another organization's refused actions left %d live sessions, want 1", n)
	}
}

// TestAdminsChangeOnlyPeopleTheyOutrank checks that changing an account (its
// password, second factors, status, existence) needs the caller to hold every
// permission the person holds, and only an owner changes an owner, so a
// helpdesk admin can reset a colleague but not take over an owner or an admin.
func TestAdminsChangeOnlyPeopleTheyOutrank(t *testing.T) {
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	person := func(perms ...string) uuid.UUID {
		t.Helper()
		u := dbtest.User(t, organization)
		dbtest.Assign(t, u.ID, organization, dbtest.Role(t, organization, perms...))
		return u.ID
	}
	owner := dbtest.User(t, organization).ID
	var ownerRole uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, owner, organization, ownerRole)
	helpdesk := person("user.read", "user.write")
	admin := person("user.read", "user.write", "role.write")
	colleague := person("user.read")

	h := testHandler(t, &dbtest.Mailbox{})
	as := func(caller uuid.UUID) http.Handler {
		return dbtest.Serve(dbtest.Principal(caller, organization), h.Mount)
	}
	type call struct {
		method, path string
		body         any
	}
	changes := func(id uuid.UUID) []call {
		p := "/users/" + id.String()
		return []call{
			{http.MethodPost, p + "/password", map[string]any{"password": "Kx7mQ2vLp9Wz-new"}},
			{http.MethodDelete, p + "/mfa", nil},
			{http.MethodPost, p + "/sessions/revoke-all", nil},
			{http.MethodPut, p + "/mfa-required", map[string]any{"required": true}},
			{http.MethodPatch, p, map[string]any{"status": "suspended"}},
			{http.MethodDelete, p, nil},
		}
	}
	for target, code := range map[uuid.UUID]string{owner: errs.CodeRBACTargetIsOwner, admin: errs.CodeRBACTargetOutranks} {
		for _, c := range changes(target) {
			rec := dbtest.Do(t, as(helpdesk), c.method, c.path, c.body)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), code) {
				t.Errorf("helpdesk %s %s: %d %s, want 403 %s", c.method, c.path, rec.Code, rec.Body.String(), code)
			}
		}
	}
	if rec := dbtest.Do(t, as(helpdesk), http.MethodPost, "/users/"+colleague.String()+"/password", map[string]any{"password": "Kx7mQ2vLp9Wz-new"}); rec.Code != http.StatusNoContent {
		t.Errorf("helpdesk resets a colleague's password: %d %s, want 204", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as(owner), http.MethodPost, "/users/"+admin.String()+"/password", map[string]any{"password": "Kx7mQ2vLp9Wz-new"}); rec.Code != http.StatusNoContent {
		t.Errorf("an owner resets an admin's password: %d %s, want 204", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = ANY($1) AND organization_id = $2 AND status = 'active' AND deleted_at IS NULL`,
		[]uuid.UUID{owner, admin}, organization); n != 2 {
		t.Errorf("%d of the owner and admin still active, want both", n)
	}
}
