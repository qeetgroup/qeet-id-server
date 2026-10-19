//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
)

// TestSoftDeleteCutsTheUserOffAndRecordsIt pins soft delete to what suspend
// already does, in one transaction: every session ends, the deletion is
// audited with who did it, user.deleted is queued for subscribers, and the
// answer says what was deleted. Restoring brings the account back but none of
// the sessions it had.
func TestSoftDeleteCutsTheUserOffAndRecordsIt(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("softdel"))
	admin := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, admin, tenantID)
	uma := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, uma, tenantID)

	authSvc := auth.NewService(testPool, user.NewRepository(testPool), mustIssuer())
	for i := 0; i < 2; i++ {
		if _, err := authSvc.IssuePair(ctx, uma, tenantID, "198.51.100.7", "browser", "password"); err != nil {
			t.Fatalf("sign in: %v", err)
		}
	}
	liveSessions := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`, uma).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		return n
	}
	if liveSessions(t) != 2 {
		t.Fatalf("setup: live sessions = %d, want 2", liveSessions(t))
	}

	r := chi.NewRouter()
	r.Use(withPrincipal(admin, tenantID))
	(&user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New()}).Mount(r)
	do := func(method, path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
		return rr
	}

	t.Run("deleting answers with what was deleted and who did it", func(t *testing.T) {
		rr := do(http.MethodDelete, "/users/"+uma.String())
		var got struct {
			ID        uuid.UUID  `json:"id"`
			DeletedAt *string    `json:"deleted_at"`
			DeletedBy *uuid.UUID `json:"deleted_by"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil {
			t.Fatalf("delete: status %d, body %q; want 200 with the deleted user", rr.Code, rr.Body.String())
		}
		if got.ID != uma || got.DeletedAt == nil || got.DeletedBy == nil || *got.DeletedBy != admin {
			t.Fatalf("delete answered %+v", got)
		}
	})

	t.Run("every session of the deleted user has ended", func(t *testing.T) {
		if n := liveSessions(t); n != 0 {
			t.Fatalf("live sessions after delete = %d, want 0", n)
		}
	})

	t.Run("the deletion is audited with the actor, organization and target", func(t *testing.T) {
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit.events WHERE action = 'user.deleted' AND tenant_id = $1
			    AND actor_user_id = $2 AND resource_id = $3`, tenantID, admin, uma).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if n != 1 {
			t.Fatalf("user.deleted audit rows = %d, want 1", n)
		}
	})

	t.Run("user.deleted is queued for subscribers", func(t *testing.T) {
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM platform.outbox WHERE event_type = 'user.deleted' AND aggregate_id = $1`, uma).Scan(&n); err != nil {
			t.Fatalf("count outbox: %v", err)
		}
		if n != 1 {
			t.Fatalf("user.deleted outbox events = %d, want 1", n)
		}
	})

	t.Run("the recycle bin shows who deleted the user", func(t *testing.T) {
		rr := do(http.MethodGet, "/users/deleted")
		var got struct {
			Items []struct {
				ID        uuid.UUID  `json:"id"`
				DeletedBy *uuid.UUID `json:"deleted_by"`
			} `json:"items"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil {
			t.Fatalf("list deleted: %d %s", rr.Code, rr.Body.String())
		}
		for _, it := range got.Items {
			if it.ID == uma {
				if it.DeletedBy == nil || *it.DeletedBy != admin {
					t.Fatalf("deleted_by = %v, want %s", it.DeletedBy, admin)
				}
				return
			}
		}
		t.Fatal("the deleted user is missing from the recycle bin")
	})

	t.Run("restoring revives none of the old sessions", func(t *testing.T) {
		if rr := do(http.MethodPost, "/users/"+uma.String()+"/restore"); rr.Code != http.StatusOK {
			t.Fatalf("restore: %d %s", rr.Code, rr.Body.String())
		}
		if n := liveSessions(t); n != 0 {
			t.Fatalf("live sessions after restore = %d, want 0", n)
		}
		var deletedBy *uuid.UUID
		if err := testPool.QueryRow(ctx, `SELECT deleted_by FROM "user".users WHERE id = $1`, uma).Scan(&deletedBy); err != nil {
			t.Fatalf("read user: %v", err)
		}
		if deletedBy != nil {
			t.Fatalf("deleted_by = %v after restore, want none", deletedBy)
		}
	})
}
