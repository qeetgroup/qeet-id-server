//go:build integration

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/tests/apitest"
)

// TestOrganizationsCannotReachEachOther checks that an owner of one organization sees only their
// own people, and is refused another organization's data whichever way they ask: its routes, its
// member's id, or a change to it.
func TestOrganizationsCannotReachEachOther(t *testing.T) {
	s := apitest.Start(t)
	a, b := s.NewOwner(), s.NewOwner()
	orgA, orgB := "/v1/organizations/"+a.OrganizationID.String(), "/v1/organizations/"+b.OrganizationID.String()

	own := s.Do(http.MethodGet, "/v1/users", a.Token, nil).Want(t, http.StatusOK)
	if !strings.Contains(string(own.Body), a.Email) || strings.Contains(string(own.Body), b.Email) {
		t.Fatalf("A's member list: %s, want A's owner and not B's", own.Body)
	}
	if res := s.Do(http.MethodGet, "/v1/users/"+b.UserID.String(), a.Token, nil); res.Status != http.StatusNotFound {
		t.Errorf("A read B's owner: %d %s, want 404", res.Status, res.Body)
	}
	for _, path := range []string{orgB, orgB + "/roles", orgB + "/audit", orgB + "/domains", orgB + "/users/" + b.UserID.String() + "/sign-ins"} {
		res := s.Do(http.MethodGet, path, a.Token, nil)
		if res.Status == http.StatusOK || strings.Contains(string(res.Body), b.Email) {
			t.Errorf("A read %s: %d %s", path, res.Status, res.Body)
		}
	}
	s.Do(http.MethodGet, orgA+"/roles", a.Token, nil).Want(t, http.StatusOK)
	if res := s.Do(http.MethodPatch, orgB, a.Token, map[string]string{"name": "Taken over"}); res.Status < 400 {
		t.Errorf("A renamed B's organization: %d %s", res.Status, res.Body)
	}
	var organization struct {
		Name string `json:"name"`
	}
	s.Do(http.MethodGet, orgB, b.Token, nil).Want(t, http.StatusOK).JSON(t, &organization)
	if organization.Name == "Taken over" {
		t.Error("B's organization was renamed by A")
	}
}
