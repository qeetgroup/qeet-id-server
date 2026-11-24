//go:build integration

package activity

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestOneEventByID checks that an organization's event is fetched by its id
// with its metadata, and that another organization's id answers 404.
func TestOneEventByID(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	mine, theirs := uuid.New(), uuid.New()
	for id, owner := range map[uuid.UUID]uuid.UUID{mine: organization, theirs: other} {
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
			INSERT INTO audit.events (id, organization_id, actor_user_id, actor_type, action, resource_type, user_agent, metadata, created_at)
			VALUES ($1, $2, $3, 'user', 'user.updated', 'user', 'Mozilla/5.0', '{"fields": ["name"]}', NOW())
		`, id, owner, admin.ID); err != nil {
			t.Fatal(err)
		}
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, dbtest.Pool(t), NewHub(nil)).Mount)
	base := "/organizations/" + organization.String() + "/activity/"

	rec := dbtest.Do(t, h, http.MethodGet, base+mine.String(), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), mine.String()) || !strings.Contains(rec.Body.String(), `"fields"`) {
		t.Errorf("own event: %d %s, want it with its metadata", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, h, http.MethodGet, base+theirs.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization's event: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+other.String()+"/activity/"+theirs.String(), nil); rec.Code != http.StatusForbidden {
		t.Errorf("naming another organization in the path: %d, want 403", rec.Code)
	}
}
