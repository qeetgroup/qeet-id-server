//go:build integration

package organization

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// TestOrganizationPickerListsEveryOrganization checks that the organization
// picker, asked for while signed in to one organization and so scoped to it by
// row-level security, and the organization list name every organization the
// person belongs to, their own one included though they hold no role there,
// and no other.
func TestOrganizationPickerListsEveryOrganization(t *testing.T) {
	h, _, _ := newHandler(t)
	home, other, unrelated := dbtest.Organization(t), dbtest.Organization(t), dbtest.Organization(t)
	a := dbtest.User(t, home, other)
	dbtest.User(t, unrelated, unrelated)
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodGet, "/me/organizations", nil)
	ids := dbtest.IDs(t, rec)
	if len(ids) != 2 || !slices.Contains(ids, home) || !slices.Contains(ids, other) {
		t.Errorf("picker lists %v; want only %s and %s", ids, home, other)
	}
	if strings.Contains(rec.Body.String(), `"roles":null`) {
		t.Errorf("picker gives a member with no role null roles, want []: %s", rec.Body.String())
	}
	// A sign-in to the other organization outlasts its session: the picker
	// still shows when it was last used.
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO audit.events (organization_id, actor_user_id, actor_type, action, resource_type, created_at)
		VALUES ($1, $2, 'user', 'auth.login_succeeded', 'session', NOW() - interval '10 days')`, other, a.ID); err != nil {
		t.Fatal(err)
	}
	var picker struct {
		Items []EligibleOrganization `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodGet, "/me/organizations", nil), &picker)
	for _, o := range picker.Items {
		if o.ID == other && (o.LastUsedAt == nil || time.Since(*o.LastUsedAt) < 9*24*time.Hour) {
			t.Errorf("the other organization's last use %v, want the sign-in 10 days ago", o.LastUsedAt)
		}
	}
	listed, _, err := h.Repo.List(dbtest.Context(t), a.ID, 50, paging.Cursor{})
	if err != nil || len(listed) != 2 || !slices.ContainsFunc(listed, func(o Organization) bool { return o.ID == home }) {
		t.Errorf("organization list %+v, %v; want %s and %s", listed, err, home, other)
	}
}
