//go:build integration

package gdpr

import (
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAnErasureRequestNamesItsPersonUntilErased checks that an erasure
// request keeps the email and name of the person it was filed for, and its
// grace period, until the erasure runs, and then no longer.
func TestAnErasureRequestNamesItsPersonUntilErased(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	person := account(t, organization)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET display_name = 'Asha Iyer' WHERE id = $1`, person.ID); err != nil {
		t.Fatal(err)
	}
	svc := NewService(dbtest.Pool(t), 30*24*time.Hour)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), requests(t, svc).Mount)
	var req Request
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, "/gdpr/purge", map[string]any{"user_id": person.ID}), &req)
	if req.SubjectEmail == nil || *req.SubjectEmail != person.Email || req.SubjectName == nil || *req.SubjectName != "Asha Iyer" ||
		req.Redacted || req.GraceDays != 30 {
		t.Fatalf("the filed request: %+v, want the person, a 30-day grace and nothing redacted", req)
	}
	due(t, req.ID)
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []Request `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/gdpr/purge", nil), &list)
	if len(list.Items) != 1 || list.Items[0].SubjectEmail != nil || list.Items[0].SubjectName != nil || !list.Items[0].Redacted {
		t.Errorf("the erased request: %+v, want the person redacted", list.Items)
	}
}
