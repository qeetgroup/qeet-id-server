//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authzen"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// denyFixture is one organisation behind the production authorization chain
// (RequireAuth, EnforceTenantScope, rbac.Enforce with the composed decider and
// bootstrap.RoutePolicies), with the three check surfaces and the user list.
type denyFixture struct {
	issuer   *tokens.Issuer
	repo     *rbac.Repository
	rebac    *rebac.Service
	abac     *abac.Service
	router   http.Handler
	tenantID uuid.UUID
}

func newDenyFixture(t *testing.T, ctx context.Context) *denyFixture {
	t.Helper()
	f := &denyFixture{
		issuer: mustIssuer(), repo: rbac.NewRepository(testPool),
		rebac: rebac.NewService(testPool), abac: abac.NewService(testPool),
		tenantID: createTenant(t, ctx, uniqueSlug("deny")),
	}
	decider := decide.New(f.repo, f.rebac, f.abac)
	authSvc := auth.NewService(testPool, user.NewRepository(testPool), f.issuer)
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: f.issuer}))
		r.Use(httpx.EnforceTenantScope)
		r.Use(rbac.Enforce(decider, bootstrap.RoutePolicies()))
		(&rbac.Handler{Repo: f.repo, Decider: decider, Validate: validator.New()}).Mount(r)
		(&rebac.Handler{Service: f.rebac, Decider: decider}).Mount(r)
		(&authzen.Handler{Service: authzen.NewService(f.repo, f.rebac, decider)}).Mount(r)
		(&user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), SignIns: authSvc}).Mount(r)
	})
	f.router = r
	return f
}

// member creates a user in the organisation holding one role with perms.
func (f *denyFixture) member(t *testing.T, ctx context.Context, perms ...string) uuid.UUID {
	t.Helper()
	u := createUserInTenant(t, ctx, f.tenantID)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	role, err := f.repo.CreateRole(ctx, tx, f.tenantID, uniqueSlug("role"), "", false)
	if err != nil {
		t.Fatalf("role: %v", err)
	}
	for _, key := range perms {
		p, err := f.repo.UpsertPermission(ctx, tx, key, key)
		if err != nil {
			t.Fatalf("permission %s: %v", key, err)
		}
		if err := f.repo.GrantPermission(ctx, tx, role.ID, p.ID); err != nil {
			t.Fatalf("grant %s: %v", key, err)
		}
	}
	if err := f.repo.AssignRole(ctx, tx, u, f.tenantID, role.ID, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return u
}

func (f *denyFixture) do(t *testing.T, as uuid.UUID, method, path string, body any) (int, map[string]any) {
	t.Helper()
	tok, _, err := f.issuer.IssueAccess(as, f.tenantID, uuid.New(), "")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func decidedModel(out map[string]any) string {
	if by, ok := out["decided_by"].(map[string]any); ok {
		m, _ := by["model"].(string)
		return m
	}
	if ctx, ok := out["context"].(map[string]any); ok {
		return decidedModel(ctx)
	}
	return ""
}

func subjectIs(id uuid.UUID) json.RawMessage {
	return json.RawMessage(`{"attr":"subject.id","op":"eq","value":"` + id.String() + `"}`)
}

// TestDenyPolicyRefusesAtEveryEnforcementPoint reproduces QTID-313: Uma's role
// grants doc:write and user.read, and she holds a write tuple on a document.
// An attribute (ABAC) deny for Uma must refuse her at the general check, the
// relationship check, AuthZEN and the platform's route guard, while a role
// grant with no tuple still allows at the relationship check, and everyone
// else is unaffected. Before the fix every one of those said allow except the
// standalone ABAC route.
func TestDenyPolicyRefusesAtEveryEnforcementPoint(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newDenyFixture(t, ctx)
	ada := f.member(t, ctx, "role.read", "policy.read", "policy.write", "user.read") // the administrator
	uma := f.member(t, ctx, "doc:write", "user.read")
	ravi := f.member(t, ctx, "doc:write")
	bob := f.member(t, ctx, "role.read") // may run checks, may not read policies
	if _, err := f.rebac.Write(ctx, f.tenantID, "doc:42", "write", "user:"+uma.String()); err != nil {
		t.Fatalf("tuple: %v", err)
	}
	adaActor := audit.Actor{Type: "user", UserID: &ada}
	tid := f.tenantID.String()

	check := func(as uuid.UUID, who uuid.UUID, perm string) (int, map[string]any) {
		return f.do(t, as, http.MethodGet, "/v1/check?user_id="+who.String()+"&tenant_id="+tid+"&permission="+perm, nil)
	}
	relation := func(as uuid.UUID, who uuid.UUID, object string) (int, map[string]any) {
		return f.do(t, as, http.MethodPost, "/v1/tenants/"+tid+"/relation-tuples/check",
			map[string]string{"object": object, "relation": "write", "user_id": who.String()})
	}
	evaluate := func(who uuid.UUID, resType, resID, action string) (int, map[string]any) {
		return f.do(t, ada, http.MethodPost, "/v1/tenants/"+tid+"/access/v1/evaluation", map[string]any{
			"subject":  map[string]string{"type": "user", "id": who.String()},
			"resource": map[string]string{"type": resType, "id": resID}, "action": map[string]string{"name": action},
		})
	}

	// Before any policy: every surface allows Uma.
	if code, out := check(ada, uma, "doc:write"); code != http.StatusOK || out["allowed"] != true || decidedModel(out) != decide.ModelRBAC {
		t.Fatalf("before: check = %d %v, want allowed by rbac", code, out)
	}
	if code, _ := f.do(t, uma, http.MethodGet, "/v1/users", nil); code != http.StatusOK {
		t.Fatalf("before: Uma GET /v1/users = %d, want 200", code)
	}

	docDeny, err := f.abac.Create(ctx, f.tenantID, abac.CreateInput{
		Name: "block-uma-docs", Effect: "deny", ResourceType: "doc", Action: "write", Condition: subjectIs(uma), Enabled: true,
	}, adaActor)
	if err != nil {
		t.Fatalf("create doc deny: %v", err)
	}
	userDeny, err := f.abac.Create(ctx, f.tenantID, abac.CreateInput{
		Name: "block-uma-users", Effect: "deny", ResourceType: "user", Action: "read", Condition: subjectIs(uma), Enabled: true,
	}, adaActor)
	if err != nil {
		t.Fatalf("create user deny: %v", err)
	}

	t.Run("the general check refuses, naming the policy to a policy reader", func(t *testing.T) {
		code, out := check(ada, uma, "doc:write")
		if code != http.StatusOK || out["allowed"] != false || decidedModel(out) != decide.ModelABAC {
			t.Fatalf("check = %d %v, want refused by abac", code, out)
		}
		if by := out["decided_by"].(map[string]any); by["policy_id"] != docDeny.ID.String() {
			t.Fatalf("decided_by = %v, want policy %s", by, docDeny.ID)
		}
		_, hidden := check(bob, uma, "doc:write")
		if by := hidden["decided_by"].(map[string]any); hidden["allowed"] != false || by["policy_id"] != nil || by["rule"] != "an attribute policy" {
			t.Fatalf("to a caller without policy.read: %v, want the policy hidden", hidden)
		}
		_, explained := f.do(t, ada, http.MethodGet, "/v1/check?user_id="+uma.String()+"&tenant_id="+tid+"&permission=doc:write&explain=true", nil)
		if trace, _ := explained["trace"].([]any); len(trace) == 0 || explained["reason"] == nil {
			t.Fatalf("explain = %v, want a trace and a reason", explained)
		}
	})

	t.Run("the relationship check refuses despite the tuple", func(t *testing.T) {
		if code, out := relation(ada, uma, "doc:42"); code != http.StatusOK || out["allowed"] != false || decidedModel(out) != decide.ModelABAC {
			t.Fatalf("relation check = %d %v, want refused by abac", code, out)
		}
	})

	t.Run("AuthZEN refuses both questions", func(t *testing.T) {
		if code, out := evaluate(uma, "permission", "", "doc:write"); code != http.StatusOK || out["decision"] != false || decidedModel(out) != decide.ModelABAC {
			t.Fatalf("authzen permission = %d %v, want refused by abac", code, out)
		}
		if code, out := evaluate(uma, "doc", "42", "write"); code != http.StatusOK || out["decision"] != false {
			t.Fatalf("authzen relation = %d %v, want refused", code, out)
		}
	})

	t.Run("the platform's route guard refuses", func(t *testing.T) {
		if code, _ := f.do(t, uma, http.MethodGet, "/v1/users", nil); code != http.StatusForbidden {
			t.Fatalf("Uma GET /v1/users = %d, want 403", code)
		}
		if code, _ := f.do(t, ada, http.MethodGet, "/v1/users", nil); code != http.StatusOK {
			t.Fatalf("Ada GET /v1/users = %d, want 200: the deny is Uma's only", code)
		}
	})

	t.Run("a role grant without a tuple still allows at the relationship check", func(t *testing.T) {
		if code, out := relation(ada, ravi, "doc:43"); code != http.StatusOK || out["allowed"] != true || decidedModel(out) != decide.ModelRBAC {
			t.Fatalf("Ravi relation check = %d %v, want allowed by his role", code, out)
		}
		if code, out := evaluate(ravi, "doc", "43", "write"); out["decision"] != true {
			t.Fatalf("Ravi authzen relation = %d %v, want allowed", code, out)
		}
	})

	t.Run("another organisation is refused before any engine", func(t *testing.T) {
		other := createTenant(t, ctx, uniqueSlug("deny-other")).String()
		if code, _ := f.do(t, ada, http.MethodGet, "/v1/check?user_id="+uma.String()+"&tenant_id="+other+"&permission=doc:write", nil); code != http.StatusForbidden {
			t.Fatalf("check in another organisation = %d, want 403", code)
		}
		if code, _ := f.do(t, ada, http.MethodPost, "/v1/tenants/"+other+"/access/v1/evaluation", map[string]any{}); code != http.StatusForbidden {
			t.Fatalf("authzen in another organisation = %d, want 403", code)
		}
	})

	t.Run("removing the deny lifts it at once", func(t *testing.T) {
		if err := f.abac.Delete(ctx, userDeny.ID, f.tenantID, adaActor); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if code, _ := f.do(t, uma, http.MethodGet, "/v1/users", nil); code != http.StatusOK {
			t.Fatalf("Uma GET /v1/users after the deny was removed = %d, want 200", code)
		}
	})

	t.Run("a deny that would lock its author out is refused", func(t *testing.T) {
		_, err := f.abac.Create(ctx, f.tenantID, abac.CreateInput{
			Name: "block-all", Effect: "deny", ResourceType: "*", Action: "*", Condition: json.RawMessage(`{}`), Enabled: true,
		}, adaActor)
		if !errors.Is(err, errs.ErrABACPolicyLocksOut) {
			t.Fatalf("deny-everything = %v, want abac.policy_locks_out", err)
		}
	})
}

// TestBrokenPolicyRefuses: a policy whose condition can't be evaluated (here
// written past the API's validation) refuses at the route guard and the check
// rather than letting the request through.
func TestBrokenPolicyRefuses(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newDenyFixture(t, ctx)
	ada := f.member(t, ctx, "role.read", "user.read")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.abac_policies (tenant_id, name, effect, resource_type, action, condition, priority, enabled)
		VALUES ($1, 'broken', 'deny', 'user', 'read', '{"attr":"subject.id","op":"bogus","value":1}'::jsonb, 0, true)
	`, f.tenantID); err != nil {
		t.Fatalf("insert broken policy: %v", err)
	}
	if code, _ := f.do(t, ada, http.MethodGet, "/v1/users", nil); code != http.StatusForbidden {
		t.Fatalf("GET /v1/users with a broken matching policy = %d, want 403", code)
	}
	code, out := f.do(t, ada, http.MethodGet, "/v1/check?user_id="+ada.String()+"&tenant_id="+f.tenantID.String()+"&permission=user.read", nil)
	if code != http.StatusOK || out["allowed"] != false || decidedModel(out) != decide.ModelABAC {
		t.Fatalf("check with a broken matching policy = %d %v, want refused by abac", code, out)
	}
}
