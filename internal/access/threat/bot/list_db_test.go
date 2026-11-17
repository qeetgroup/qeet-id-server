//go:build integration

package bot

import (
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestDetectionsArePagedAndNameTheirAccount checks that the detections page
// by cursor with a total, name the account the attempt was for, and say how
// its sign-in from the address then ended.
func TestDetectionsArePagedAndNameTheirAccount(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	victim := dbtest.User(t, organization, organization)
	svc := NewService(pool)
	if _, err := pool.Exec(ctx, `INSERT INTO auth.bot_settings (organization_id, ua_check, honeypot, captcha, signature, score_threshold) VALUES ($1, TRUE, FALSE, FALSE, FALSE, 0.9)`, organization); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		svc.Evaluate(ctx, victim.Email, "198.51.100.7", "python-requests/2.31")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit.events (organization_id, actor_type, actor_user_id, action, resource_type, ip)
		VALUES ($1, 'user', $2, 'auth.sign_in_failed', 'user', '198.51.100.7')`, organization, victim.ID); err != nil {
		t.Fatal(err)
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	var page struct {
		Recent     []Event `json:"recent"`
		NextCursor string  `json:"next_cursor"`
		Total      int     `json:"total"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/security/bots?limit=2", nil), &page)
	if page.Total != 3 || len(page.Recent) != 2 || page.NextCursor == "" {
		t.Fatalf("first page: %d of %d, cursor %q; want 2 of 3 and a cursor", len(page.Recent), page.Total, page.NextCursor)
	}
	e := page.Recent[0]
	if e.UserID == nil || *e.UserID != victim.ID || e.UserEmail == nil || *e.UserEmail != victim.Email || e.Outcome != "failed" {
		t.Errorf("detection %+v, want the victim's account and its failed sign-in", e)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/security/bots?limit=2&cursor="+page.NextCursor, nil), &page)
	if len(page.Recent) != 1 || page.NextCursor != "" {
		t.Errorf("second page: %d, cursor %q; want the last one", len(page.Recent), page.NextCursor)
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/security/bots?verdict=maybe", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown verdict: %d, want 400", rec.Code)
	}
}
