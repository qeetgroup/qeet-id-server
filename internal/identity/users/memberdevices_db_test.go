//go:build integration

package user

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAdministratorsSeeAndRemoveAMembersPasskeys checks that an
// administrator lists a member's passkeys and removes one, audited and
// emailed, but not the account's last way to sign in, not from an account
// another organisation shares or manages, and not someone else's passkey.
func TestAdministratorsSeeAndRemoveAMembersPasskeys(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	solo := dbtest.User(t, tenant, tenant)
	shared := dbtest.User(t, tenant, tenant, other)
	guest := dbtest.User(t, other, other, tenant)
	passkey := func(userID uuid.UUID, name string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
			INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, name)
			VALUES ($1, $2, 'pk', $3) RETURNING id`, userID, []byte(dbtest.Unique("cred")), name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	laptop, phone := passkey(solo.ID, "Laptop"), passkey(solo.ID, "Phone")
	sharedKey, guestKey := passkey(shared.ID, "Shared"), passkey(guest.ID, "Guest")
	passkey(shared.ID, "Spare")
	passkey(guest.ID, "Spare")
	mailbox := &dbtest.Mailbox{}
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, mailbox).Mount)
	path := func(u uuid.UUID) string { return "/tenants/" + tenant.String() + "/users/" + u.String() + "/passkeys" }
	remove := func(name string, u, key uuid.UUID, status int, code string) {
		t.Helper()
		rec := dbtest.Do(t, as, http.MethodDelete, path(u)+"/"+key.String(), nil)
		if rec.Code != status || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), status, code)
		}
	}

	rec := dbtest.Do(t, as, http.MethodGet, path(solo.ID), nil)
	var page struct {
		Items []MemberPasskey `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); rec.Code != http.StatusOK || err != nil || len(page.Items) != 2 || *page.Items[0].Name != "Laptop" {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as, http.MethodGet, path(guest.ID), nil); rec.Code != http.StatusOK {
		t.Errorf("listing a member from elsewhere: %d, want 200", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/tenants/"+other.String()+"/users/"+solo.ID.String()+"/passkeys", nil); rec.Code != http.StatusForbidden {
		t.Errorf("listing through another organisation's path: %d, want 403", rec.Code)
	}

	remove("another person's passkey", solo.ID, sharedKey, http.StatusNotFound, errs.CodeNotFound)
	remove("a shared account's passkey", shared.ID, sharedKey, http.StatusForbidden, errs.CodeUserCredentialsShared)
	remove("a member from elsewhere's passkey", guest.ID, guestKey, http.StatusForbidden, errs.CodeUserManagedElsewhere)
	if mailbox.Len() != 0 || dbtest.Count(t, `SELECT count(*) FROM auth.passkey_credentials WHERE id = ANY($1)`, []uuid.UUID{sharedKey, guestKey}) != 2 {
		t.Error("a refused removal removed a passkey or told someone")
	}

	remove("one of two passkeys", solo.ID, laptop, http.StatusNoContent, "")
	if dbtest.Count(t, `SELECT count(*) FROM auth.passkey_credentials WHERE id = $1`, laptop) != 0 || audited(t, tenant, "passkey.admin_deleted", solo.ID) != 1 {
		t.Error("removing a passkey left it or wasn't audited")
	}
	if m := mailbox.Last(t); m.To != solo.Email || !strings.Contains(m.Body, `"Laptop"`) {
		t.Errorf("the notice went to %s saying %q, want %s naming Laptop", m.To, m.Body, solo.Email)
	}
	remove("the last way to sign in", solo.ID, phone, http.StatusConflict, errs.CodeAuthLastSignInMethod)
	if dbtest.Count(t, `SELECT count(*) FROM auth.passkey_credentials WHERE id = $1`, phone) != 1 {
		t.Error("the account's last passkey was removed")
	}
}

// TestAdministratorsEndOneOfAMembersSessions checks that an administrator ends
// one session of a member in their organisation, audited, leaving the others,
// and that a session elsewhere or already ended answers 404.
func TestAdministratorsEndOneOfAMembersSessions(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	member := dbtest.User(t, other, other, tenant)
	here, there := session(t, member.ID, tenant, ""), session(t, member.ID, other, "")
	session(t, member.ID, tenant, "")
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, &dbtest.Mailbox{}).Mount)
	end := func(name string, id uuid.UUID, status int) {
		t.Helper()
		rec := dbtest.Do(t, as, http.MethodDelete, "/tenants/"+tenant.String()+"/users/"+member.ID.String()+"/sessions/"+id.String(), nil)
		if rec.Code != status {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body.String(), status)
		}
	}
	end("a session in the organisation", here, http.StatusNoContent)
	end("the same again", here, http.StatusNotFound)
	end("a session in another organisation", there, http.StatusNotFound)
	if liveSessions(t, member.ID) != 2 || audited(t, tenant, "session.admin_revoked", member.ID) != 1 {
		t.Errorf("%d live sessions, %d audited; want the other two left and one record", liveSessions(t, member.ID), audited(t, tenant, "session.admin_revoked", member.ID))
	}
}
