//go:build integration

package organization

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestCreateOrganization checks that a verified account creates a free
// organization as its owner, holding every permission, with an audit record,
// an event and a token pair for it; and that an unverified account, a paid
// plan and a taken slug are refused.
func TestCreateOrganization(t *testing.T) {
	h, _, _ := newHandler(t)
	slug := dbtest.Unique("acme")

	unverified := dbtest.User(t, uuid.Nil)
	for _, tc := range []struct {
		name   string
		as     uuid.UUID
		body   map[string]any
		status int
		code   string
	}{
		{"an unverified account", unverified.ID, map[string]any{"slug": dbtest.Unique("org"), "name": "Acme"}, http.StatusForbidden, CodeEmailNotVerified},
		{"a paid plan", verifiedAccount(t).ID, map[string]any{"slug": dbtest.Unique("org"), "name": "Acme", "plan": "pro"}, http.StatusPaymentRequired, errs.CodeBillingCheckoutRequired},
	} {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(tc.as, uuid.Nil), h.Mount), http.MethodPost, "/organizations", tc.body)
		if code := errorCode(t, rec); rec.Code != tc.status || code != tc.code {
			t.Errorf("%s: %d %s, want %d %s", tc.name, rec.Code, code, tc.status, tc.code)
		}
	}

	owner := verifiedAccount(t)
	ownerP := signedIn(t, owner.ID, uuid.Nil)
	asOwner := dbtest.Serve(ownerP, h.Mount)
	rec := dbtest.Do(t, asOwner, http.MethodPost, "/organizations", map[string]any{"slug": slug, "name": "Acme"})
	var created struct {
		Organization Organization `json:"organization"`
		Roles        []string     `json:"roles"`
		AccessToken  string       `json:"access_token"`
		SessionID    uuid.UUID    `json:"session_id"`
	}
	dbtest.Decode(t, rec, &created)
	id := created.Organization.ID
	if rec.Code != http.StatusCreated || created.Organization.Plan != "free" || created.Organization.Status != "active" || !slices.Equal(created.Roles, []string{"owner"}) {
		t.Fatalf("create: %d %s; want a free, active organization owned by the caller", rec.Code, rec.Body.String())
	}
	if created.AccessToken == "" || dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND organization_id = $2`, created.SessionID, id) != 1 {
		t.Error("no token pair for a session in the new organization")
	}
	if !continues(t, created.SessionID, *ownerP.SessionID) {
		t.Error("the new organization's session doesn't continue the caller's sign-in")
	}
	if missing := dbtest.Count(t, `
		SELECT count(*) FROM rbac.permissions p WHERE NOT EXISTS (
			SELECT 1 FROM rbac.user_roles ur JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
			WHERE ur.user_id = $1 AND ur.organization_id = $2 AND rp.permission_id = p.id)
	`, owner.ID, id); missing != 0 {
		t.Errorf("the owner lacks %d permissions in the new organization", missing)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2`, owner.ID, id); n != 1 {
		t.Error("the new organization didn't become the owner's home organization")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'organization.created' AND resource_id = $1 AND actor_user_id = $2`, id, owner.ID); n != 1 {
		t.Error("the creation was not audited as the owner's")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = 'organization.created' AND aggregate_id = $1`, id); n != 1 {
		t.Error("the creation was not queued as an event")
	}

	again := dbtest.Do(t, asOwner, http.MethodPost, "/organizations", map[string]any{"slug": slug, "name": "Acme again"})
	if code := errorCode(t, again); again.Code != http.StatusConflict || code != errs.CodeOrgSlugTaken {
		t.Errorf("a taken slug: %d %s, want 409 %s", again.Code, code, errs.CodeOrgSlugTaken)
	}
}

// TestOrganizationLifecycleIsTheOwners checks that only an owner changes an
// organization's status or deletes it; that it can't suspend itself; that a
// suspension made another way ends and announces its sessions and is audited,
// and reactivating restores none; and that deleting it is scheduled, can be
// called off, and once due ends the sessions opened since and hides it.
func TestOrganizationLifecycleIsTheOwners(t *testing.T) {
	ctx := dbtest.Context(t)
	h, authSvc, signals := newHandler(t)
	owner := verifiedAccount(t)
	org, err := h.Repo.CreateWithOwner(ctx, CreateInput{Slug: dbtest.Unique("org"), Name: "Acme"}, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	other := dbtest.Organization(t)
	admin := dbtest.User(t, org.ID)
	dbtest.Assign(t, admin.ID, org.ID, dbtest.Role(t, org.ID, "organization.read", "organization.write"))
	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, org.ID), h.Mount)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, org.ID), h.Mount)
	path := "/organizations/" + org.ID.String()
	signIn := func() *auth.TokenPair {
		t.Helper()
		pair, err := authSvc.IssuePair(ctx, owner.ID, org.ID, "192.0.2.1", "test", "password")
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		return pair
	}
	ended := func(pair *auth.TokenPair) bool {
		return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NOT NULL`, pair.SessionID) == 1
	}
	audited := func(action string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND resource_id = $2`, action, org.ID)
	}
	refused := func(name string, rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if got := errorCode(t, rec); rec.Code != status || got != code {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, got, status, code)
		}
	}

	refused("the owner suspends it", dbtest.Do(t, asOwner, http.MethodPatch, path, map[string]any{"status": "suspended"}), http.StatusForbidden, CodeSelfSuspend)
	refused("an admin changes its status", dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"status": "active"}), http.StatusForbidden, CodeOwnerOnly)
	refused("an admin deletes it", dbtest.Do(t, asAdmin, http.MethodDelete, path, nil), http.StatusForbidden, CodeOwnerOnly)
	if rec := dbtest.Do(t, asOwner, http.MethodPatch, "/organizations/"+other.String(), map[string]any{"status": "active"}); rec.Code != http.StatusForbidden {
		t.Errorf("changing another organization: %d, want 403", rec.Code)
	}

	before := signIn()
	if _, err := h.Repo.Update(ctx, org.ID, UpdateInput{Status: new("suspended")}, statusChange(h.Signals, org.ID, audit.Actor{Type: "system"}), nil); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if !ended(before) {
		t.Error("suspending the organization left its session live")
	}
	if _, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: before.RefreshToken}); err == nil {
		t.Error("a session of the suspended organization was renewed")
	}
	if !slices.Equal(signals.reasons, []string{sessionsignal.ReasonOrganizationSuspended}) {
		t.Errorf("announced %v; want one session ended as %s", signals.reasons, sessionsignal.ReasonOrganizationSuspended)
	}
	if audited("organization.suspended") != 1 || dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = 'organization.suspended' AND aggregate_id = $1`, org.ID) != 1 {
		t.Error("the suspension was not audited and queued as an event")
	}
	if rec := dbtest.Do(t, asOwner, http.MethodPatch, path, map[string]any{"status": "active"}); rec.Code != http.StatusOK || audited("organization.reactivated") != 1 {
		t.Fatalf("reactivate: %d %s, audited %d times", rec.Code, rec.Body.String(), audited("organization.reactivated"))
	}
	if !ended(before) {
		t.Error("reactivating the organization restored a session it ended")
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"name": "Acme Ltd"})
	var renamed Organization
	dbtest.Decode(t, rec, &renamed)
	if rec.Code != http.StatusOK || renamed.Name != "Acme Ltd" || len(signals.reasons) != 1 {
		t.Errorf("an admin renames it: %d %s, %d announcements; want the new name and no lifecycle effect", rec.Code, rec.Body.String(), len(signals.reasons))
	}

	since := signIn()
	if rec := dbtest.Do(t, asOwner, http.MethodDelete, path, nil); rec.Code != http.StatusAccepted || audited("organization.deletion_scheduled") != 1 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	var scheduled Organization
	dbtest.Decode(t, dbtest.Do(t, asOwner, http.MethodGet, path, nil), &scheduled)
	if scheduled.DeletionDueAt == nil || ended(since) {
		t.Errorf("after scheduling: %+v, session ended %v; want it working with its deletion due", scheduled, ended(since))
	}
	// The list of a member's organizations shows the same date.
	listed := func() *time.Time {
		var page struct {
			Items []Organization `json:"items"`
		}
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/organizations", nil), &page)
		for _, it := range page.Items {
			if it.ID == org.ID {
				return it.DeletionDueAt
			}
		}
		t.Fatal("the organization is missing from its admin's list")
		return nil
	}
	if due := listed(); due == nil || !due.Equal(*scheduled.DeletionDueAt) {
		t.Errorf("listed deletion_due_at %v, want %v as the organization itself says", due, scheduled.DeletionDueAt)
	}
	refused("delete it twice", dbtest.Do(t, asOwner, http.MethodDelete, path, nil), http.StatusConflict, CodeDeletionScheduled)
	refused("an admin calls it off", dbtest.Do(t, asAdmin, http.MethodPost, path+"/deletion/cancel", nil), http.StatusForbidden, CodeOwnerOnly)
	rec = dbtest.Do(t, asOwner, http.MethodPost, path+"/deletion/cancel", nil)
	var kept Organization
	dbtest.Decode(t, rec, &kept)
	if rec.Code != http.StatusOK || kept.DeletionDueAt != nil || audited("organization.deletion_cancelled") != 1 {
		t.Errorf("call it off: %d %s", rec.Code, rec.Body.String())
	}
	if due := listed(); due != nil {
		t.Errorf("listed deletion_due_at %v once called off, want none", due)
	}
	refused("call it off twice", dbtest.Do(t, asOwner, http.MethodPost, path+"/deletion/cancel", nil), http.StatusConflict, CodeDeletionNotScheduled)

	if rec := dbtest.Do(t, asOwner, http.MethodDelete, path, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("delete again: %d %s", rec.Code, rec.Body.String())
	}
	if n, err := DeleteDue(ctx, h.Repo, h.Signals); err != nil || n != 0 || ended(since) {
		t.Errorf("before it is due: deleted %d, %v, session ended %v; want nothing deleted", n, err, ended(since))
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.organizations SET deletion_due_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, org.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := DeleteDue(ctx, h.Repo, h.Signals); err != nil || n != 1 {
		t.Fatalf("once due: deleted %d, %v; want the organization", n, err)
	}
	if !ended(since) || audited("organization.deleted") != 1 {
		t.Error("deleting the organization left its session live or was not audited")
	}
	if rec := dbtest.Do(t, asOwner, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a deleted organization: %d, want 404", rec.Code)
	}
}

// TestOrganizationProfileChangesAreAudited checks that an update to an
// organization's name, region, logo or metadata is recorded as one
// organization.updated naming every field that changed (the name and region with
// their old and new values, the logo and metadata by name only); that an update
// changing nothing records nothing; and that a status change is recorded as
// such, not as an update.
func TestOrganizationProfileChangesAreAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _, _ := newHandler(t)
	owner := verifiedAccount(t)
	org, err := h.Repo.CreateWithOwner(ctx, CreateInput{Slug: dbtest.Unique("org"), Name: "Acme", Metadata: map[string]any{"tier": "gold"}}, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	admin := dbtest.User(t, org.ID)
	dbtest.Assign(t, admin.ID, org.ID, dbtest.Role(t, org.ID, "organization.read", "organization.write"))
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, org.ID), h.Mount)
	path := "/organizations/" + org.ID.String()
	type record struct {
		Changed []string                  `json:"changed"`
		Changes map[string]map[string]any `json:"changes"`
	}
	updates := func() []record {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata FROM audit.events
			WHERE organization_id = $1 AND action = 'organization.updated' AND resource_id = $1 AND actor_user_id = $2
			ORDER BY created_at`, org.ID, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []record
		for rows.Next() {
			var raw []byte
			var r record
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	patch := func(body map[string]any) {
		t.Helper()
		if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, body); rec.Code != http.StatusOK {
			t.Fatalf("update %v: %d %s", body, rec.Code, rec.Body.String())
		}
	}

	patch(map[string]any{"name": "Acme Ltd", "region": org.Region, "logo_url": "data:image/png;base64,AAAA", "metadata": map[string]any{"tier": "platinum"}})
	got := updates()
	want := record{
		Changed: []string{"name", "logo_url", "metadata"},
		Changes: map[string]map[string]any{"name": {"from": "Acme", "to": "Acme Ltd"}},
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("recorded %+v, want %+v", got, want)
	}
	patch(map[string]any{"name": "Acme Ltd", "metadata": map[string]any{"tier": "platinum"}})
	if got := updates(); len(got) != 1 {
		t.Errorf("an update changing nothing was recorded: %+v", got)
	}
	patch(map[string]any{"logo_url": ""})
	if got := updates(); len(got) != 2 || !reflect.DeepEqual(got[1].Changed, []string{"logo_url"}) || len(got[1].Changes) != 0 {
		t.Errorf("recorded %+v, want a second naming only the logo", got)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE resource_id = $1 AND strpos(metadata::text, 'base64') > 0`, org.ID); n != 0 {
		t.Errorf("%d audit records hold the logo itself", n)
	}

	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, org.ID), h.Mount)
	if rec := dbtest.Do(t, asOwner, http.MethodPatch, path, map[string]any{"status": "active"}); rec.Code != http.StatusOK {
		t.Fatalf("set the status: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'organization.updated' AND resource_id = $1`, org.ID); n != 2 {
		t.Errorf("%d organization.updated records after an unchanged status, want 2", n)
	}
}

// TestCreateOrganizationFromAnother checks that a member signed in to one
// organization, and so scoped to it by row-level security, creates another
// and is its owner, with a token pair for it.
func TestCreateOrganizationFromAnother(t *testing.T) {
	h, _, _ := newHandler(t)
	home := dbtest.Organization(t)
	a := verifiedAccount(t)
	dbtest.Assign(t, a.ID, home, dbtest.Role(t, home))
	rec := dbtest.Do(t, dbtest.Serve(signedIn(t, a.ID, home), h.Mount), http.MethodPost, "/organizations",
		map[string]any{"slug": dbtest.Unique("org"), "name": "Second"})
	var created struct {
		OrganizationID uuid.UUID `json:"organization_id"`
		AccessToken    string    `json:"access_token"`
	}
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.AccessToken == "" {
		t.Fatalf("create: %d %s; want the organization and a token pair for it", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id AND r.organization_id = ur.organization_id
		WHERE ur.user_id = $1 AND ur.organization_id = $2 AND r.name = 'owner'
	`, a.ID, created.OrganizationID); n != 1 {
		t.Error("the creator is not the new organization's owner")
	}

	rec = dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodPost, "/organizations",
		map[string]any{"slug": dbtest.Unique("org"), "name": "Third"})
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("create without a session: %d %s; want the organization and no token pair", rec.Code, rec.Body.String())
	}
}
