//go:build integration

package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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
	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, uuid.Nil), h.Mount)
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

// TestSuspendAndDeleteEndSessions checks that suspending an organisation
// ends and announces its sessions, so they can't be renewed, and is audited;
// that reactivating it restores none; that a rename has no lifecycle effect;
// that another organisation can't be changed; and that deleting it ends the
// sessions opened since and hides it.
func TestSuspendAndDeleteEndSessions(t *testing.T) {
	ctx := dbtest.Context(t)
	h, authSvc, signals := newHandler(t)
	owner := verifiedAccount(t)
	org, err := h.Repo.CreateWithOwner(ctx, CreateInput{Slug: dbtest.Unique("org"), Name: "Acme"}, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	other := dbtest.Tenant(t)
	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, org.ID), h.Mount)
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

	before := signIn()
	if rec := dbtest.Do(t, asOwner, http.MethodPatch, path, map[string]any{"status": "suspended"}); rec.Code != http.StatusOK {
		t.Fatalf("suspend: %d %s", rec.Code, rec.Body.String())
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
	rec := dbtest.Do(t, asOwner, http.MethodPatch, path, map[string]any{"name": "Acme Ltd"})
	var renamed Tenant
	dbtest.Decode(t, rec, &renamed)
	if rec.Code != http.StatusOK || renamed.Name != "Acme Ltd" || len(signals.reasons) != 1 {
		t.Errorf("rename: %d %s, %d announcements; want the new name and no lifecycle effect", rec.Code, rec.Body.String(), len(signals.reasons))
	}
	if rec := dbtest.Do(t, asOwner, http.MethodPatch, "/tenants/"+other.String(), map[string]any{"status": "suspended"}); rec.Code != http.StatusForbidden {
		t.Errorf("suspending another organisation: %d, want 403", rec.Code)
	}

	since := signIn()
	if rec := dbtest.Do(t, asOwner, http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if !ended(since) || audited("tenant.deleted") != 1 {
		t.Error("deleting the organisation left its session live or was not audited")
	}
	if rec := dbtest.Do(t, asOwner, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a deleted organisation: %d, want 404", rec.Code)
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
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodPost, "/tenants",
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
}

// TestOrganisationPickerListsEveryOrganisation checks that the organisation
// picker, asked for while signed in to one organisation and so scoped to it by
// row-level security, lists every organisation the person belongs to.
func TestOrganisationPickerListsEveryOrganisation(t *testing.T) {
	h, _, _ := newHandler(t)
	home, other := dbtest.Tenant(t), dbtest.Tenant(t)
	a := dbtest.User(t, home, home, other)
	ids := dbtest.IDs(t, dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodGet, "/me/organizations", nil))
	if !slices.Contains(ids, home) || !slices.Contains(ids, other) {
		t.Errorf("picker lists %v; want both %s and %s", ids, home, other)
	}
}
