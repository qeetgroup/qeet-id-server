//go:build integration

package scim

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAdminListsPageAndConfigTellsTheLastRequest checks that the console's
// lists of SCIM-provisioned people and groups page with a total, groups with
// their live members, and that the config tells how the last change the
// identity provider sent was answered.
func TestAdminListsPageAndConfigTellsTheLastRequest(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t, pool)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	var people []uuid.UUID
	for range 3 {
		u := dbtest.User(t, organization, organization)
		if _, err := pool.Exec(ctx, `UPDATE account.users SET provisioned_via = 'scim', external_id = $2 WHERE id = $1`, u.ID, u.ID.String()); err != nil {
			t.Fatal(err)
		}
		people = append(people, u.ID)
	}
	var group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name, external_id, provisioned_via) VALUES ($1, 'Engineering', 'eng', 'scim') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	for _, id := range people[:2] {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (organization_id, group_id, user_id) VALUES ($1, $2, $3)`, organization, group, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET deleted_at = NOW() WHERE id = $1`, people[1]); err != nil {
		t.Fatal(err)
	}

	type page struct {
		Items []struct {
			ID      uuid.UUID `json:"id"`
			Members int       `json:"members"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
		Total      int    `json:"total"`
	}
	base := "/organizations/" + organization.String() + "/scim/"
	var first, second page
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"users?limit=1", nil), &first)
	if first.Total != 2 || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first page of people: %+v; want 1 of the 2 live ones, with a cursor", first)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"users?limit=1&cursor="+first.NextCursor, nil), &second)
	if len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ID == first.Items[0].ID {
		t.Errorf("second page of people: %+v; want the other one, and no cursor", second)
	}
	var groups page
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"groups", nil), &groups)
	if groups.Total != 1 || len(groups.Items) != 1 || groups.Items[0].ID != group || groups.Items[0].Members != 1 {
		t.Errorf("groups: %+v; want Engineering with its one live member", groups)
	}

	cfg, err := svc.Config(ctx, organization)
	if err != nil || cfg.LastRequest != nil {
		t.Fatalf("config before any change: %+v, %v; want no last request", cfg, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO organization.directory_events (id, organization_id, connection_id, operation, trigger_type, resource_type, started_at, duration_ms, http_status, status, error_code, reason)
		VALUES ($1, $2, $3, 'post', 'push', 'user', NOW(), 12, 409, 'failed', 'DIR-409', 'scim.uniqueness')`,
		uuid.New(), organization, "scim:"+organization.String()); err != nil {
		t.Fatal(err)
	}
	cfg, err = svc.Config(ctx, organization)
	if err != nil || cfg.LastRequest == nil || cfg.LastRequest.HTTPStatus != 409 || cfg.LastRequest.Reason != "scim.uniqueness" || cfg.LastRequest.ErrorCode != "DIR-409" {
		t.Errorf("config after a refused change: %+v, %v; want its 409, DIR-409 and scim.uniqueness", cfg.LastRequest, err)
	}
}
