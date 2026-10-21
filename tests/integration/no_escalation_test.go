//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestNobodyHandsOutAuthorityTheyDontHold: managing roles or members was
// checked by one permission and nothing more, so a helpdesk holding role.write
// or user.write could make itself owner, add secret.read to its own role, or
// invite its own second address as owner. Granting a permission now needs the
// caller to hold it; giving a role — directly, to a group or by invitation —
// needs every permission the role carries; the owner role is given only by an
// owner; and an owner may still give anything.
func TestNobodyHandsOutAuthorityTheyDontHold(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	repo := rbac.NewRepository(testPool)
	rbacH := &rbac.Handler{Repo: repo, Service: rbac.NewService(repo), Validate: validator.New()}
	inviteH := &invite.Handler{Service: invite.NewService(testPool, &mailbox{}, time.Hour, "http://console.test"),
		Validate: validator.New(), GrantCheck: repo.CheckGrantRole}

	var ownerID uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO "user".users (email) VALUES ($1) RETURNING id`, uniqueSlug("owner")+"@example.com").Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	org, err := tenant.NewRepository(testPool).CreateWithOwner(ctx, tenant.CreateInput{Slug: uniqueSlug("escalation"), Name: "Escalation"}, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	perm := func(key string) uuid.UUID {
		var id uuid.UUID
		if err := testPool.QueryRow(ctx, `INSERT INTO rbac.permissions (key) VALUES ($1)
			ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id`, key).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	role := func(name string, keys ...string) uuid.UUID {
		var id uuid.UUID
		if err := testPool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, $2) RETURNING id`, org.ID, uniqueSlug(name)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if _, err := testPool.Exec(ctx, `INSERT INTO rbac.role_permissions (role_id, permission_id) VALUES ($1, $2)`, id, perm(k)); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	var ownerRole uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM rbac.roles WHERE tenant_id = $1 AND is_system AND name = 'owner'`, org.ID).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	helpdeskRole := role("helpdesk", "role.write", "user.write")
	helpdesk := createUserInTenant(t, ctx, org.ID)
	if _, err := testPool.Exec(ctx, `INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, helpdesk, org.ID, helpdeskRole); err != nil {
		t.Fatal(err)
	}

	as := func(userID uuid.UUID) http.Handler {
		r := chi.NewRouter()
		r.Route("/v1", func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					uid, tid := userID, org.ID
					next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), &httpx.Principal{ActorType: "user", UserID: &uid, TenantID: &tid})))
				})
			})
			rbacH.Mount(r)
			inviteH.MountAuthed(r)
		})
		return r
	}
	call := func(h http.Handler, method, path string, body any) (int, string, map[string]any) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(method, path, &buf))
		var out struct {
			Error struct {
				Code     string         `json:"code"`
				Metadata map[string]any `json:"metadata"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out.Error.Code, out.Error.Metadata
	}
	assignPath := func(user, role uuid.UUID) string {
		return "/v1/users/" + user.String() + "/tenants/" + org.ID.String() + "/roles/" + role.String()
	}
	desk, owner := as(helpdesk), as(ownerID)

	if code, errCode, meta := call(desk, http.MethodPost, "/v1/roles/"+helpdeskRole.String()+"/permissions/"+perm("secret.read").String(), nil); code != http.StatusForbidden ||
		errCode != "rbac.grant_exceeds_caller" || meta["permission"] != "secret.read" {
		t.Fatalf("helpdesk grants secret.read to its own role = %d %s %v, want 403 rbac.grant_exceeds_caller naming secret.read", code, errCode, meta)
	}
	if code, errCode, _ := call(desk, http.MethodPost, assignPath(helpdesk, ownerRole), nil); code != http.StatusForbidden || errCode != "rbac.owner_only" {
		t.Fatalf("helpdesk makes itself owner = %d %s, want 403 rbac.owner_only", code, errCode)
	}
	if code, errCode, _ := call(desk, http.MethodPost, "/v1/invites", map[string]any{"email": uniqueSlug("second") + "@example.com", "role_id": ownerRole}); code != http.StatusForbidden || errCode != "rbac.owner_only" {
		t.Fatalf("helpdesk invites an owner = %d %s, want 403 rbac.owner_only", code, errCode)
	}
	vault := role("vault", "secret.read")
	if code, errCode, _ := call(desk, http.MethodPost, "/v1/invites", map[string]any{"email": uniqueSlug("third") + "@example.com", "role_id": vault}); code != http.StatusForbidden || errCode != "rbac.grant_exceeds_caller" {
		t.Fatalf("helpdesk invites with a role beyond it = %d %s, want 403 rbac.grant_exceeds_caller", code, errCode)
	}

	member := createUserInTenant(t, ctx, org.ID)
	if code, errCode, _ := call(desk, http.MethodPost, "/v1/roles/"+role("deputy").String()+"/permissions/"+perm("user.write").String(), nil); code != http.StatusNoContent {
		t.Fatalf("helpdesk grants a permission it holds = %d %s, want 204", code, errCode)
	}
	if code, errCode, _ := call(desk, http.MethodPost, assignPath(member, role("reader", "user.write")), nil); code != http.StatusNoContent {
		t.Fatalf("helpdesk assigns a role within its own authority = %d %s, want 204", code, errCode)
	}
	if code, errCode, _ := call(owner, http.MethodPost, assignPath(member, ownerRole), nil); code != http.StatusNoContent {
		t.Fatalf("an owner makes someone owner = %d %s, want 204", code, errCode)
	}
	if code, errCode, _ := call(owner, http.MethodPost, "/v1/roles/"+helpdeskRole.String()+"/permissions/"+perm("secret.read").String(), nil); code != http.StatusNoContent {
		t.Fatalf("an owner grants any permission = %d %s, want 204", code, errCode)
	}
}
