//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	agent "github.com/qeetgroup/qeet-id-server/internal/developer/agents"
	authhook "github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	opratelimits "github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
	cachelimit "github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestSecurityMutationsEmitAtomicEvidence(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mutation-evidence"))
	actorID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, actorID, tenantID)
	actor := audit.Actor{UserID: &actorID, Type: "user", IP: "198.51.100.10", UserAgent: "evidence-test", RequestID: "evidence-matrix"}
	box := testEnvelope(t)
	policy := egress.DevelopmentPolicy()

	agentService := agent.NewService(testPool, mustIssuer())
	if _, err := agentService.CreateWithActor(ctx, tenantID, "evidence-agent", []string{"user.read"}, 300, actorID, actor); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	authHookService := authhook.NewService(testPool, policy)
	authHookService.SetCipher(box)
	if _, err := authHookService.CreateWithActor(ctx, tenantID, "http://127.0.0.1/hook", "secret", true, actor); err != nil {
		t.Fatalf("create auth hook: %v", err)
	}
	siemService := siem.NewService(testPool, policy)
	siemService.SetCipher(box)
	if _, err := siemService.CreateWithActor(ctx, tenantID, "http", "http://127.0.0.1/events", "token", actor); err != nil {
		t.Fatalf("create SIEM sink: %v", err)
	}
	domainService := domainverify.NewService(testPool)
	if _, err := domainService.AddWithActor(ctx, tenantID, uniqueSlug("evidence")+".example.com", actor); err != nil {
		t.Fatalf("add domain: %v", err)
	}
	rebacService := rebac.NewService(testPool)
	if _, err := rebacService.WriteWithActor(ctx, tenantID, "document:evidence", "viewer", "user:"+actorID.String(), actor); err != nil {
		t.Fatalf("write ReBAC tuple: %v", err)
	}
	vcService := vc.NewService(testPool, mustIssuer())
	if _, err := vcService.IssueWithActor(ctx, tenantID, actorID.String(), "EvidenceCredential", map[string]any{"level": "verified"}, 300, actor); err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	store := cachelimit.NewMemStore()
	tenantLimiter := cachelimit.NewTenantLimiter(store, 100, 500, testPool, "tenant")
	userLimiter := cachelimit.NewTenantLimiter(store, 30, 100, testPool, "user")
	apiKeyLimiter := cachelimit.NewTenantLimiter(store, 50, 200, testPool, "api_key")
	rateHandler := &opratelimits.Handler{
		Pool: testPool, TenantLim: tenantLimiter, UserLim: userLimiter, APIKeyLim: apiKeyLimiter,
		Defaults: opratelimits.Defaults{TenantRate: 100, TenantCapacity: 500, UserRate: 30, UserCapacity: 100, APIKeyRate: 50, APIKeyCapacity: 200},
	}
	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(withPrincipal(actorID, tenantID))
	rateHandler.Mount(router)
	rateBody, _ := json.Marshal(map[string]any{
		"tenant":  map[string]any{"rate": 90, "capacity": 450},
		"user":    map[string]any{"rate": 25, "capacity": 80},
		"api_key": map[string]any{"rate": 40, "capacity": 150},
	})
	rateRequest := httptest.NewRequest(http.MethodPut, "/tenants/"+tenantID.String()+"/rate-limits", bytes.NewReader(rateBody))
	rateRequest.Header.Set("Content-Type", "application/json")
	rateRecorder := httptest.NewRecorder()
	router.ServeHTTP(rateRecorder, rateRequest)
	if rateRecorder.Code != http.StatusOK {
		t.Fatalf("update rate limits status = %d: %s", rateRecorder.Code, rateRecorder.Body.String())
	}
	userHandler := &user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(validator.WithRequiredStructEnabled())}
	userRouter := chi.NewRouter()
	userRouter.Use(chimiddleware.RequestID)
	userRouter.Use(withPrincipal(actorID, tenantID))
	userHandler.Mount(userRouter)
	bulkBody, _ := json.Marshal(map[string]any{
		"users": []map[string]any{{"email": uniqueSlug("bulk-evidence") + "@example.com", "display_name": "Evidence User"}},
	})
	bulkRequest := httptest.NewRequest(http.MethodPost, "/users/bulk", bytes.NewReader(bulkBody))
	bulkRequest.Header.Set("Content-Type", "application/json")
	bulkRecorder := httptest.NewRecorder()
	userRouter.ServeHTTP(bulkRecorder, bulkRequest)
	if bulkRecorder.Code != http.StatusOK {
		t.Fatalf("bulk import status = %d: %s", bulkRecorder.Code, bulkRecorder.Body.String())
	}

	wantActions := map[string]bool{
		"agent.created": false, "auth_hook.created": false, "siem.sink_created": false,
		"domain.created": false, "rebac.tuple_written": false, "credential.issued": false,
		"rate_limits.updated": false, "user.bulk_imported": false,
	}
	rows, err := testPool.Query(ctx, `
		SELECT action, actor_user_id, actor_type, tenant_id, resource_id, request_id
		FROM audit.events WHERE tenant_id = $1 AND action = ANY($2::text[])
	`, tenantID, []string{"agent.created", "auth_hook.created", "siem.sink_created", "domain.created", "rebac.tuple_written", "credential.issued", "rate_limits.updated", "user.bulk_imported"})
	if err != nil {
		t.Fatalf("query mutation audit: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var actionName, actorType, requestID string
		var gotActor, gotTenant, resourceID uuid.UUID
		if err := rows.Scan(&actionName, &gotActor, &actorType, &gotTenant, &resourceID, &requestID); err != nil {
			t.Fatalf("scan mutation audit: %v", err)
		}
		if gotActor != actorID || actorType != "user" || gotTenant != tenantID || resourceID == uuid.Nil || requestID == "" {
			t.Fatalf("incomplete audit provenance for %s: actor=%s type=%q tenant=%s resource=%s request=%q", actionName, gotActor, actorType, gotTenant, resourceID, requestID)
		}
		wantActions[actionName] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate mutation audit: %v", err)
	}
	for actionName, found := range wantActions {
		if !found {
			t.Errorf("missing audit event %s", actionName)
		}
	}
	var outboxEvents int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM platform.outbox
		WHERE event_type = ANY($1::text[])
	`, []string{"agent.created", "auth_hook.created", "siem.sink_created", "domain.created", "rebac.tuple_written", "credential.issued", "rate_limits.updated", "user.bulk_imported"}).Scan(&outboxEvents); err != nil {
		t.Fatalf("count mutation outbox: %v", err)
	}
	if outboxEvents < len(wantActions) {
		t.Fatalf("mutation outbox events = %d, want at least %d", outboxEvents, len(wantActions))
	}
}
