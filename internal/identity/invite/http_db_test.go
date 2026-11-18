//go:build integration

package invite

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestInvitationListTakesTheOrganizationFromTheCaller checks that the list of
// invitations answers only for the caller's own organization, even without the
// router's organization guard in front: another organization's in the path is
// refused, not read.
func TestInvitationListTakesTheOrganizationFromTheCaller(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	mine, theirs := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, mine, mine)
	theirEmail := dbtest.Unique("invitee") + "@example.test"
	if _, _, err := h.Service.Create(ctx, CreateInput{OrganizationID: theirs, Email: theirEmail}, audit.Actor{}); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), dbtest.Principal(admin.ID, mine))))
		})
	})
	h.MountAuthed(r)
	rec := dbtest.Do(t, r, http.MethodGet, "/organizations/"+theirs.String()+"/invites", nil)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), theirEmail) {
		t.Errorf("list another organization's invitations: %d %.120s, want 403", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, r, http.MethodGet, "/organizations/"+mine.String()+"/invites", nil); rec.Code != http.StatusOK {
		t.Errorf("list the caller's own: %d %s", rec.Code, rec.Body.String())
	}
}
