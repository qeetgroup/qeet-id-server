//go:build integration

package tenant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// announced records the session.revoked signals sent, by reason.
type announced struct {
	mu      sync.Mutex
	reasons []string
}

func (a *announced) enqueue(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ string, payload any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p, ok := payload.(map[string]any); ok {
		if reason, ok := p["reason"].(string); ok {
			a.reasons = append(a.reasons, reason)
		}
	}
	return nil
}

// newHandler returns the organisation handler, issuing real token pairs, and
// what it announces.
func newHandler(t *testing.T) (*Handler, *auth.Service, *announced) {
	t.Helper()
	pool := dbtest.Pool(t)
	signals := &announced{}
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	return &Handler{
		Repo:        NewRepository(pool),
		Validate:    validator.New(validator.WithRequiredStructEnabled()),
		AuthService: authSvc,
		Signals:     sessionsignal.New(signals.enqueue),
		OwnerCheck:  rbac.NewRepository(pool).IsOwner,
	}, authSvc, signals
}

// verifiedAccount creates an account with a verified email and no
// organisation.
func verifiedAccount(t *testing.T) dbtest.Account {
	t.Helper()
	a := dbtest.User(t, uuid.Nil)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	return a
}

// signedIn returns userID's principal in tenant (uuid.Nil: none) with a live
// session that signed in an hour ago and ends in two.
func signedIn(t *testing.T, userID, tenant uuid.UUID) *httpx.Principal {
	t.Helper()
	var tenantArg any
	if tenant != uuid.Nil {
		tenantArg = tenant
	}
	var session uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO auth.sessions (user_id, tenant_id, signed_in_at, expires_at)
		VALUES ($1, $2, NOW() - INTERVAL '1 hour', NOW() + INTERVAL '2 hours') RETURNING id
	`, userID, tenantArg).Scan(&session); err != nil {
		t.Fatal(err)
	}
	p := dbtest.Principal(userID, tenant)
	p.SessionID = &session
	return p
}

// continues reports whether session continues from's sign-in: the same
// sign-in time, and an end no later.
func continues(t *testing.T, session, from uuid.UUID) bool {
	t.Helper()
	return dbtest.Count(t, `
		SELECT count(*) FROM auth.sessions s JOIN auth.sessions f ON f.id = $2
		WHERE s.id = $1 AND s.signed_in_at = f.signed_in_at AND s.expires_at <= f.expires_at
	`, session, from) == 1
}

// errorCode returns the error code of a JSON error answer.
func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	dbtest.Decode(t, rec, &body)
	return body.Error.Code
}

// TestCreateOrganisation checks that a verified account creates a free
// organisation as its owner, holding every permission, with an audit record,
// an event and a token pair for it; and that an unverified account, a paid
// plan and a taken slug are refused.
func TestCreateOrganisation(t *testing.T) {
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
		{"an unverified account", unverified.ID, map[string]any{"slug": dbtest.Unique("org"), "name": "Acme"}, http.StatusForbidden, errs.CodeEmailNotVerified},
		{"a paid plan", verifiedAccount(t).ID, map[string]any{"slug": dbtest.Unique("org"), "name": "Acme", "plan": "pro"}, http.StatusPaymentRequired, errs.CodeBillingCheckoutRequired},
	} {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(tc.as, uuid.Nil), h.Mount), http.MethodPost, "/tenants", tc.body)
		if code := errorCode(t, rec); rec.Code != tc.status || code != tc.code {
			t.Errorf("%s: %d %s, want %d %s", tc.name, rec.Code, code, tc.status, tc.code)
		}
	}

	owner := verifiedAccount(t)
	ownerP := signedIn(t, owner.ID, uuid.Nil)
	asOwner := dbtest.Serve(ownerP, h.Mount)
	rec := dbtest.Do(t, asOwner, http.MethodPost, "/tenants", map[string]any{"slug": slug, "name": "Acme"})
	var created struct {
		Tenant      Tenant    `json:"tenant"`
		Roles       []string  `json:"roles"`
		AccessToken string    `json:"access_token"`
		SessionID   uuid.UUID `json:"session_id"`
	}
	dbtest.Decode(t, rec, &created)
	id := created.Tenant.ID
	if rec.Code != http.StatusCreated || created.Tenant.Plan != "free" || created.Tenant.Status != "active" || !slices.Equal(created.Roles, []string{"owner"}) {
		t.Fatalf("create: %d %s; want a free, active organisation owned by the caller", rec.Code, rec.Body.String())
	}
	if created.AccessToken == "" || dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND tenant_id = $2`, created.SessionID, id) != 1 {
		t.Error("no token pair for a session in the new organisation")
	}
	if !continues(t, created.SessionID, *ownerP.SessionID) {
		t.Error("the new organisation's session doesn't continue the caller's sign-in")
	}
	if missing := dbtest.Count(t, `
		SELECT count(*) FROM rbac.permissions p WHERE NOT EXISTS (
			SELECT 1 FROM rbac.user_roles ur JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
			WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND rp.permission_id = p.id)
	`, owner.ID, id); missing != 0 {
		t.Errorf("the owner lacks %d permissions in the new organisation", missing)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND tenant_id = $2`, owner.ID, id); n != 1 {
		t.Error("the new organisation didn't become the owner's home organisation")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'tenant.created' AND resource_id = $1 AND actor_user_id = $2`, id, owner.ID); n != 1 {
		t.Error("the creation was not audited as the owner's")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = 'tenant.created' AND aggregate_id = $1`, id); n != 1 {
		t.Error("the creation was not queued as an event")
	}

	again := dbtest.Do(t, asOwner, http.MethodPost, "/tenants", map[string]any{"slug": slug, "name": "Acme again"})
	if code := errorCode(t, again); again.Code != http.StatusConflict || code != errs.CodeOrgSlugTaken {
		t.Errorf("a taken slug: %d %s, want 409 %s", again.Code, code, errs.CodeOrgSlugTaken)
	}
}

// TestOrganisationLifecycleIsTheOwners checks that only an owner changes an
// organisation's status or deletes it; that it can't suspend itself; that a
// suspension made another way ends and announces its sessions and is audited,
// and reactivating restores none; and that deleting it is scheduled, can be
// called off, and once due ends the sessions opened since and hides it.
func TestOrganisationLifecycleIsTheOwners(t *testing.T) {
	ctx := dbtest.Context(t)
	h, authSvc, signals := newHandler(t)
	owner := verifiedAccount(t)
	org, err := h.Repo.CreateWithOwner(ctx, CreateInput{Slug: dbtest.Unique("org"), Name: "Acme"}, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	other := dbtest.Tenant(t)
	admin := dbtest.User(t, org.ID)
	dbtest.Assign(t, admin.ID, org.ID, dbtest.Role(t, org.ID, "tenant.read", "tenant.write"))
	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, org.ID), h.Mount)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, org.ID), h.Mount)
	path := "/tenants/" + org.ID.String()
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

	refused("the owner suspends it", dbtest.Do(t, asOwner, http.MethodPatch, path, map[string]any{"status": "suspended"}), http.StatusForbidden, errs.CodeTenantSelfSuspend)
	refused("an admin changes its status", dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"status": "active"}), http.StatusForbidden, errs.CodeTenantOwnerOnly)
	refused("an admin deletes it", dbtest.Do(t, asAdmin, http.MethodDelete, path, nil), http.StatusForbidden, errs.CodeTenantOwnerOnly)
	if rec := dbtest.Do(t, asOwner, http.MethodPatch, "/tenants/"+other.String(), map[string]any{"status": "active"}); rec.Code != http.StatusForbidden {
		t.Errorf("changing another organisation: %d, want 403", rec.Code)
	}

	before := signIn()
	if _, err := h.Repo.Update(ctx, org.ID, UpdateInput{Status: ptr("suspended")}, statusChange(h.Signals, org.ID, audit.Actor{Type: "system"}), nil); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if !ended(before) {
		t.Error("suspending the organisation left its session live")
	}
	if _, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: before.RefreshToken}); err == nil {
		t.Error("a session of the suspended organisation was renewed")
	}
	if !slices.Equal(signals.reasons, []string{sessionsignal.ReasonTenantSuspended}) {
		t.Errorf("announced %v; want one session ended as %s", signals.reasons, sessionsignal.ReasonTenantSuspended)
	}
	if audited("tenant.suspended") != 1 || dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = 'tenant.suspended' AND aggregate_id = $1`, org.ID) != 1 {
		t.Error("the suspension was not audited and queued as an event")
	}
	if rec := dbtest.Do(t, asOwner, http.MethodPatch, path, map[string]any{"status": "active"}); rec.Code != http.StatusOK || audited("tenant.reactivated") != 1 {
		t.Fatalf("reactivate: %d %s, audited %d times", rec.Code, rec.Body.String(), audited("tenant.reactivated"))
	}
	if !ended(before) {
		t.Error("reactivating the organisation restored a session it ended")
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"name": "Acme Ltd"})
	var renamed Tenant
	dbtest.Decode(t, rec, &renamed)
	if rec.Code != http.StatusOK || renamed.Name != "Acme Ltd" || len(signals.reasons) != 1 {
		t.Errorf("an admin renames it: %d %s, %d announcements; want the new name and no lifecycle effect", rec.Code, rec.Body.String(), len(signals.reasons))
	}

	since := signIn()
	if rec := dbtest.Do(t, asOwner, http.MethodDelete, path, nil); rec.Code != http.StatusAccepted || audited("tenant.deletion_scheduled") != 1 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	var scheduled Tenant
	dbtest.Decode(t, dbtest.Do(t, asOwner, http.MethodGet, path, nil), &scheduled)
	if scheduled.DeletionDueAt == nil || ended(since) {
		t.Errorf("after scheduling: %+v, session ended %v; want it working with its deletion due", scheduled, ended(since))
	}
	// The list of a member's organisations shows the same date.
	listed := func() *time.Time {
		var page struct {
			Items []Tenant `json:"items"`
		}
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/tenants", nil), &page)
		for _, it := range page.Items {
			if it.ID == org.ID {
				return it.DeletionDueAt
			}
		}
		t.Fatal("the organisation is missing from its admin's list")
		return nil
	}
	if due := listed(); due == nil || !due.Equal(*scheduled.DeletionDueAt) {
		t.Errorf("listed deletion_due_at %v, want %v as the organisation itself says", due, scheduled.DeletionDueAt)
	}
	refused("delete it twice", dbtest.Do(t, asOwner, http.MethodDelete, path, nil), http.StatusConflict, errs.CodeTenantDeletionScheduled)
	refused("an admin calls it off", dbtest.Do(t, asAdmin, http.MethodPost, path+"/deletion/cancel", nil), http.StatusForbidden, errs.CodeTenantOwnerOnly)
	rec = dbtest.Do(t, asOwner, http.MethodPost, path+"/deletion/cancel", nil)
	var kept Tenant
	dbtest.Decode(t, rec, &kept)
	if rec.Code != http.StatusOK || kept.DeletionDueAt != nil || audited("tenant.deletion_cancelled") != 1 {
		t.Errorf("call it off: %d %s", rec.Code, rec.Body.String())
	}
	if due := listed(); due != nil {
		t.Errorf("listed deletion_due_at %v once called off, want none", due)
	}
	refused("call it off twice", dbtest.Do(t, asOwner, http.MethodPost, path+"/deletion/cancel", nil), http.StatusConflict, errs.CodeTenantDeletionNotScheduled)

	if rec := dbtest.Do(t, asOwner, http.MethodDelete, path, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("delete again: %d %s", rec.Code, rec.Body.String())
	}
	if n, err := DeleteDue(ctx, h.Repo, h.Signals); err != nil || n != 0 || ended(since) {
		t.Errorf("before it is due: deleted %d, %v, session ended %v; want nothing deleted", n, err, ended(since))
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE tenant.tenants SET deletion_due_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, org.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := DeleteDue(ctx, h.Repo, h.Signals); err != nil || n != 1 {
		t.Fatalf("once due: deleted %d, %v; want the organisation", n, err)
	}
	if !ended(since) || audited("tenant.deleted") != 1 {
		t.Error("deleting the organisation left its session live or was not audited")
	}
	if rec := dbtest.Do(t, asOwner, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a deleted organisation: %d, want 404", rec.Code)
	}
}

// ptr is a pointer to v.
func ptr[T any](v T) *T { return &v }

// TestOrganisationProfileChangesAreAudited checks that an update to an
// organisation's name, region, logo or metadata is recorded as one
// tenant.updated naming every field that changed (the name and region with
// their old and new values, the logo and metadata by name only); that an update
// changing nothing records nothing; and that a status change is recorded as
// such, not as an update.
func TestOrganisationProfileChangesAreAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _, _ := newHandler(t)
	owner := verifiedAccount(t)
	org, err := h.Repo.CreateWithOwner(ctx, CreateInput{Slug: dbtest.Unique("org"), Name: "Acme", Metadata: map[string]any{"tier": "gold"}}, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	admin := dbtest.User(t, org.ID)
	dbtest.Assign(t, admin.ID, org.ID, dbtest.Role(t, org.ID, "tenant.read", "tenant.write"))
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, org.ID), h.Mount)
	path := "/tenants/" + org.ID.String()
	type record struct {
		Changed []string                  `json:"changed"`
		Changes map[string]map[string]any `json:"changes"`
	}
	updates := func() []record {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata FROM audit.events
			WHERE tenant_id = $1 AND action = 'tenant.updated' AND resource_id = $1 AND actor_user_id = $2
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

	patch(map[string]any{"name": "Acme Ltd", "region": "eu-west-1", "logo_url": "data:image/png;base64,AAAA", "metadata": map[string]any{"tier": "platinum"}})
	got := updates()
	want := record{
		Changed: []string{"name", "region", "logo_url", "metadata"},
		Changes: map[string]map[string]any{"name": {"from": "Acme", "to": "Acme Ltd"}, "region": {"from": org.Region, "to": "eu-west-1"}},
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
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'tenant.updated' AND resource_id = $1`, org.ID); n != 2 {
		t.Errorf("%d tenant.updated records after an unchanged status, want 2", n)
	}
}

// TestCreateOrganisationFromAnother checks that a member signed in to one
// organisation, and so scoped to it by row-level security, creates another
// and is its owner, with a token pair for it.
func TestCreateOrganisationFromAnother(t *testing.T) {
	h, _, _ := newHandler(t)
	home := dbtest.Tenant(t)
	a := verifiedAccount(t)
	dbtest.Assign(t, a.ID, home, dbtest.Role(t, home))
	rec := dbtest.Do(t, dbtest.Serve(signedIn(t, a.ID, home), h.Mount), http.MethodPost, "/tenants",
		map[string]any{"slug": dbtest.Unique("org"), "name": "Second"})
	var created struct {
		TenantID    uuid.UUID `json:"tenant_id"`
		AccessToken string    `json:"access_token"`
	}
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.AccessToken == "" {
		t.Fatalf("create: %d %s; want the organisation and a token pair for it", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND r.name = 'owner'
	`, a.ID, created.TenantID); n != 1 {
		t.Error("the creator is not the new organisation's owner")
	}

	rec = dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodPost, "/tenants",
		map[string]any{"slug": dbtest.Unique("org"), "name": "Third"})
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("create without a session: %d %s; want the organisation and no token pair", rec.Code, rec.Body.String())
	}
}

// TestOrganisationPickerListsEveryOrganisation checks that the organisation
// picker, asked for while signed in to one organisation and so scoped to it by
// row-level security, and the organisation list name every organisation the
// person belongs to, their own one included though they hold no role there,
// and no other.
func TestOrganisationPickerListsEveryOrganisation(t *testing.T) {
	h, _, _ := newHandler(t)
	home, other, unrelated := dbtest.Tenant(t), dbtest.Tenant(t), dbtest.Tenant(t)
	a := dbtest.User(t, home, other)
	dbtest.User(t, unrelated, unrelated)
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodGet, "/me/organizations", nil)
	ids := dbtest.IDs(t, rec)
	if len(ids) != 2 || !slices.Contains(ids, home) || !slices.Contains(ids, other) {
		t.Errorf("picker lists %v; want only %s and %s", ids, home, other)
	}
	if strings.Contains(rec.Body.String(), `"roles":null`) {
		t.Errorf("picker gives a member with no role null roles, want []: %s", rec.Body.String())
	}
	// A sign-in to the other organisation outlasts its session: the picker
	// still shows when it was last used.
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO audit.events (tenant_id, actor_user_id, actor_type, action, resource_type, created_at)
		VALUES ($1, $2, 'user', 'auth.login_succeeded', 'session', NOW() - interval '10 days')`, other, a.ID); err != nil {
		t.Fatal(err)
	}
	var picker struct {
		Items []EligibleOrganization `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodGet, "/me/organizations", nil), &picker)
	for _, o := range picker.Items {
		if o.ID == other && (o.LastUsedAt == nil || time.Since(*o.LastUsedAt) < 9*24*time.Hour) {
			t.Errorf("the other organisation's last use %v, want the sign-in 10 days ago", o.LastUsedAt)
		}
	}
	listed, _, err := h.Repo.List(dbtest.Context(t), a.ID, 50, "")
	if err != nil || len(listed) != 2 || !slices.ContainsFunc(listed, func(o Tenant) bool { return o.ID == home }) {
		t.Errorf("organisation list %+v, %v; want %s and %s", listed, err, home, other)
	}
}
