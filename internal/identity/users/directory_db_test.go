//go:build integration

package user

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// endSessions is a signInEnder that ends the person's sessions, the part of
// ending every sign-in that this package can see.
type endSessions struct{}

// EndAllSignIns ends userID's live sessions in tx and counts them.
func (endSessions) EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, _ string) (SignInsEnded, error) {
	ended, err := sessionsignal.EndUserSessions(ctx, tx, userID)
	return SignInsEnded{Sessions: int64(len(ended))}, err
}

// clearTOTP is an mfaResetter that removes the person's authenticator app.
type clearTOTP struct{}

// ResetForUser deletes userID's authenticator app in tx and counts it.
func (clearTOTP) ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (map[string]int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM auth.mfa_totp WHERE user_id = $1`, userID)
	return map[string]int64{"totp": tag.RowsAffected()}, err
}

// testHandler returns the user routes with a password policy that accepts
// anything, sign-ins ended by endSessions, second factors reset by clearTOTP
// and mail kept in mailbox.
func testHandler(t *testing.T, mailbox *dbtest.Mailbox) *Handler {
	t.Helper()
	return &Handler{
		Repo:           NewRepository(dbtest.Pool(t)),
		Validate:       jsonNamedValidator(),
		PasswordPolicy: func(context.Context, uuid.UUID, string, string) error { return nil },
		MFA:            clearTOTP{},
		SignIns:        endSessions{},
		Mailer:         mailbox,
	}
}

// exec runs a statement that sets up a test, failing t if it errors.
func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), sql, args...); err != nil {
		t.Fatalf("set up: %v\n%s", err, sql)
	}
}

// session gives the user a live session in tenant (nil: none) from ip ("":
// unknown) and returns its id.
func session(t *testing.T, userID uuid.UUID, tenant any, ip string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO auth.sessions (user_id, tenant_id, ip) VALUES ($1, $2, NULLIF($3, '')::inet) RETURNING id
	`, userID, tenant, ip).Scan(&id); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return id
}

// liveSessions counts the user's sessions that have not been revoked.
func liveSessions(t *testing.T, userID uuid.UUID) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`, userID)
}

// audited counts the organisation's audit events of action about resource.
func audited(t *testing.T, tenant uuid.UUID, action string, resource uuid.UUID) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2 AND resource_id = $3`, tenant, action, resource)
}

// TestCreateUserInTheCallersOrganisation checks that an administrator creates
// a person at home in their own organisation whatever the body names, with the
// password hashed and the creation audited, and that a taken email, a refused
// password or a bad address leaves no account behind.
func TestCreateUserInTheCallersOrganisation(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	otherAdmin := dbtest.User(t, other, other)
	h := testHandler(t, nil)
	h.PasswordPolicy = func(_ context.Context, _ uuid.UUID, _, plain string) error {
		if plain == "NoSymbolPassword99" {
			return errs.ErrAuthPolicyPasswordNoSymbol
		}
		return nil
	}
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	email := dbtest.Unique("new") + "@example.test"
	const plain = "Kx7mQ2vLp9Wz-new"

	rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"tenant_id": other, "email": email, "password": plain, "display_name": "New Person"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create a user: status %d (%s)", rec.Code, rec.Body.String())
	}
	var created User
	dbtest.Decode(t, rec, &created)
	if created.TenantID != tenant || created.Email != email || created.DisplayName == nil || *created.DisplayName != "New Person" || created.Status != "active" {
		t.Errorf("created %+v, want an active %s at home in the caller's organisation", created, email)
	}
	var hash string
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id = $1`, created.ID).Scan(&hash); err != nil || !password.Verify(hash, plain) {
		t.Errorf("the new user's password isn't stored as a hash of the one given (%v)", err)
	}
	if n := audited(t, tenant, "user.created", created.ID); n != 1 {
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
		{"the same email from another organisation", asOther, map[string]any{"email": email}, errs.CodeAuthEmailExists},
	} {
		rec := dbtest.Do(t, tc.as, http.MethodPost, "/users", tc.body)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("create with %s: %d %s, want 409 %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE lower(email) = lower($1)`, email); n != 1 {
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
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email IN ($1, 'not-an-email')`, refused); n != 0 {
		t.Errorf("refused creations left %d accounts", n)
	}
}

// TestCreatedUserIsListed checks that a person created in an organisation
// appears in its user list and member counts, as they do in its other views.
func TestCreatedUserIsListed(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, nil).Mount)
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
		t.Error("the organisation's user list leaves out the user it just created")
	}
	var stats UserStats
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users/stats", nil), &stats)
	if stats.Total != 2 {
		t.Errorf("the organisation counts %d users, want 2", stats.Total)
	}
}

// TestListPagesThroughTheOrganisationsMembers checks that the user list walks
// every live member of the caller's organisation exactly once by cursor or by
// offset, leaves out other organisations' people and deleted accounts, and
// shows a member's roles and groups in this organisation only.
func TestListPagesThroughTheOrganisationsMembers(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	want := []uuid.UUID{admin.ID}
	for range 4 {
		want = append(want, dbtest.User(t, tenant, tenant).ID)
	}
	guest := dbtest.User(t, other, other, tenant)
	want = append(want, guest.ID)
	outsider := dbtest.User(t, other, other)
	gone := dbtest.User(t, tenant, tenant)
	exec(t, `UPDATE "user".users SET deleted_at = NOW(), status = 'deleted' WHERE id = $1`, gone.ID)
	for _, in := range []uuid.UUID{tenant, other} {
		exec(t, `
			WITH g AS (INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id)
			INSERT INTO tenant.group_members (group_id, user_id, tenant_id) SELECT id, $3, $1 FROM g
		`, in, dbtest.Unique("group"), guest.ID)
	}
	exec(t, `INSERT INTO auth.mfa_totp (user_id, secret, confirmed_at) VALUES ($1, 'secret', NOW())`, admin.ID)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, nil).Mount)

	var walked []User
	cursor := ""
	for page := 1; ; page++ {
		if page > 3 {
			t.Fatal("the cursor walk didn't end")
		}
		path := "/users?limit=4"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		rec := dbtest.Do(t, as, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("list page %d: status %d (%s)", page, rec.Code, rec.Body.String())
		}
		var body struct {
			Items      []User `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		dbtest.Decode(t, rec, &body)
		if page == 1 && len(body.Items) != 4 {
			t.Errorf("the first page has %d users, want 4", len(body.Items))
		}
		walked = append(walked, body.Items...)
		if body.NextCursor == "" {
			break
		}
		cursor = body.NextCursor
	}
	var got []uuid.UUID
	for _, u := range walked {
		got = append(got, u.ID)
	}
	if !slices.Equal(slices.SortedFunc(slices.Values(got), uuidCompare), slices.SortedFunc(slices.Values(want), uuidCompare)) {
		t.Errorf("the cursor walk listed %v, want each of %v once (not %s or %s)", got, want, outsider.ID, gone.ID)
	}

	if ids := dbtest.IDs(t, dbtest.Do(t, as, http.MethodGet, "/users?limit=2&offset=2", nil)); len(got) == len(want) && !slices.Equal(ids, got[2:4]) {
		t.Errorf("the offset page lists %v, want %v", ids, got[2:4])
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/users?cursor=not-a-cursor", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("list with a bad cursor: %d, want 400", rec.Code)
	}

	var roleHere string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT r.name FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2
	`, guest.ID, tenant).Scan(&roleHere); err != nil {
		t.Fatal(err)
	}
	for _, u := range walked {
		if u.ID != guest.ID {
			continue
		}
		if !slices.Equal(u.Roles, []string{roleHere}) {
			t.Errorf("the guest's roles are listed as %v, want only %q from this organisation", u.Roles, roleHere)
		}
		if u.GroupsCount == nil || *u.GroupsCount != 1 {
			t.Errorf("the guest's groups are counted as %v, want 1 in this organisation", u.GroupsCount)
		}
	}

	var stats UserStats
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users/stats", nil), &stats)
	if stats != (UserStats{Total: 6, Active: 6, MFAEnabled: 1, MFAMissing: 5, NewLast30d: 6}) {
		t.Errorf("stats %+v, want 6 active members, 1 with a second factor", stats)
	}
	var trends UserTrends
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users/trends", nil), &trends)
	if len(trends.Total) != 30 || len(trends.MFAEnabled) != 30 || trends.Total[29] != 6 || trends.MFAEnabled[29] != 1 {
		t.Errorf("trends %+v, want 30 days ending at 6 members, 1 with a second factor", trends)
	}
}

// TestListShowsOnlyTheOrganisationsLastSignIn checks that the user list shows
// when and from where a member last used this organisation, not another one.
func TestListShowsOnlyTheOrganisationsLastSignIn(t *testing.T) {
	tenant, home := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	guest := dbtest.User(t, home, home, tenant)
	session(t, guest.ID, home, "198.51.100.7")
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, nil).Mount)
	var page struct {
		Items []User `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users", nil), &page)
	for _, u := range page.Items {
		if u.ID != guest.ID || (u.LastSeenIP == nil && u.LastSeenAt == nil) {
			continue
		}
		ip := ""
		if u.LastSeenIP != nil {
			ip = *u.LastSeenIP
		}
		t.Errorf("another organisation sees the member's last sign-in there: at %v from %q", u.LastSeenAt, ip)
	}
}

// TestPeopleEditOnlyTheirOwnProfile checks that /me reads and changes the
// caller's own account, keeps other metadata when setting the locale, and
// ignores fields that would change the person's standing.
func TestPeopleEditOnlyTheirOwnProfile(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	me := dbtest.User(t, tenant, tenant)
	exec(t, `UPDATE "user".users SET metadata = '{"team":"blue"}' WHERE id = $1`, me.ID)
	as := dbtest.Serve(dbtest.Principal(me.ID, tenant), testHandler(t, nil).Mount)

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
		FROM "user".users WHERE id = $1
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

// TestAvatarCanBeCleared checks that an empty avatar_url removes the avatar, as
// UpdateInput documents.
func TestAvatarCanBeCleared(t *testing.T) {
	tenant := dbtest.Tenant(t)
	me := dbtest.User(t, tenant, tenant)
	as := dbtest.Serve(dbtest.Principal(me.ID, tenant), testHandler(t, nil).Mount)
	if rec := dbtest.Do(t, as, http.MethodPatch, "/me", map[string]any{"avatar_url": "data:image/png;base64,AAAA"}); rec.Code != http.StatusOK {
		t.Fatalf("set an avatar: status %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as, http.MethodPatch, "/me", map[string]any{"avatar_url": ""}); rec.Code != http.StatusOK {
		t.Fatalf("clear the avatar: status %d (%s)", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND COALESCE(avatar_url, '') = ''`, me.ID); n != 1 {
		t.Error("the avatar is still set after clearing it")
	}
}

// TestBulkImportStaysInTheCallersOrganisation checks that a bulk import naming
// another organisation is refused before any row is created, and that an
// unknown source or an empty export is refused as a whole.
func TestBulkImportStaysInTheCallersOrganisation(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, nil).Mount)
	smuggled := dbtest.Unique("smuggled") + "@example.test"

	rec := dbtest.Do(t, as, http.MethodPost, "/users/bulk", map[string]any{"tenant_id": other, "users": []map[string]any{{"email": smuggled}}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("bulk import into another organisation: %d, want 403", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, smuggled); n != 0 {
		t.Errorf("the refused bulk import created %d users", n)
	}
	rec = dbtest.Do(t, as, http.MethodPost, "/users/bulk", map[string]any{"tenant_id": tenant, "users": []map[string]any{{"email": smuggled}}})
	var res BulkImportResult
	dbtest.Decode(t, rec, &res)
	if rec.Code != http.StatusOK || res.Succeeded != 1 {
		t.Errorf("bulk import naming the caller's organisation: %d %+v, want 1 created", rec.Code, res)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1 AND tenant_id = $2`, smuggled, tenant); n != 1 {
		t.Errorf("the bulk import created %d users in the caller's organisation, want 1", n)
	}
	if n := audited(t, tenant, "user.bulk_imported", tenant); n != 1 {
		t.Errorf("%d user.bulk_imported audit events, want 1", n)
	}

	for _, tc := range []struct {
		name, method, path string
		body               any
		want               string
	}{
		{"no rows", http.MethodPost, "/users/bulk", map[string]any{"users": []any{}}, errs.CodeValidation},
		{"an unknown source", http.MethodPost, "/users/bulk/import?source=okta", nil, errs.CodeUserImportSourceInvalid},
		{"an empty export", http.MethodPost, "/users/bulk/import?source=auth0", nil, errs.CodeUserImportEmpty},
	} {
		if rec := dbtest.Do(t, as, tc.method, tc.path, tc.body); !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("bulk import with %s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}
