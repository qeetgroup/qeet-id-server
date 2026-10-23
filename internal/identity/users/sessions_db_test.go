//go:build integration

package user

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestMemberSessionsStayInTheirTenant checks that an administrator sees only
// the sessions a member holds in the administrator's own tenant, and that only
// the member's home tenant also sees their sessions in no tenant.
func TestMemberSessionsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	member := dbtest.User(t, tenantA, tenantA, tenantB)
	adminA := dbtest.User(t, tenantA, tenantA)
	adminB := dbtest.User(t, tenantB, tenantB)
	session := func(tenant any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2) RETURNING id`, member.ID, tenant).Scan(&id); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return id
	}
	sessionA, sessionB, accountSession := session(tenantA), session(tenantB), session(nil)

	h := &Handler{Repo: NewRepository(pool)}
	for _, tc := range []struct {
		name  string
		admin uuid.UUID
		in    uuid.UUID
		want  []uuid.UUID
	}{
		{"home tenant", adminA.ID, tenantA, []uuid.UUID{sessionA, accountSession}},
		{"other tenant", adminB.ID, tenantB, []uuid.UUID{sessionB}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			as := dbtest.Serve(dbtest.Principal(tc.admin, tc.in), h.Mount)
			rec := dbtest.Do(t, as, http.MethodGet, "/users/"+member.ID.String()+"/sessions", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("list the member's sessions: status %d (%s)", rec.Code, rec.Body.String())
			}
			ids := dbtest.IDs(t, rec)
			slices.SortFunc(ids, uuidCompare)
			want := slices.Clone(tc.want)
			slices.SortFunc(want, uuidCompare)
			if !slices.Equal(ids, want) {
				t.Errorf("sessions %v, want %v", ids, want)
			}

			rec = dbtest.Do(t, as, http.MethodGet, "/users/"+member.ID.String()+"/security", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("read the member's security summary: status %d (%s)", rec.Code, rec.Body.String())
			}
			var sum SecuritySummary
			dbtest.Decode(t, rec, &sum)
			if sum.ActiveSessions != len(tc.want) {
				t.Errorf("security summary counts %d active sessions, want %d", sum.ActiveSessions, len(tc.want))
			}
		})
	}
}

func uuidCompare(a, b uuid.UUID) int {
	return slices.Compare(a[:], b[:])
}
