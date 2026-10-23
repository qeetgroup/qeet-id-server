//go:build integration

package gdpr

import (
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestExportSelfCoversEveryOrganisation checks that a person's own export,
// asked for while signed in to one organisation and so scoped to it by
// row-level security, still lists their roles in every organisation.
func TestExportSelfCoversEveryOrganisation(t *testing.T) {
	home, other := dbtest.Tenant(t), dbtest.Tenant(t)
	a := dbtest.User(t, home, home, other)
	h := &Handler{Service: NewService(dbtest.Pool(t), 30*24*time.Hour)}
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodPost, "/account/export", nil)
	var body struct {
		Profile struct {
			Email string `json:"email"`
		} `json:"profile"`
		Roles []exportSelfRole `json:"roles"`
	}
	dbtest.Decode(t, rec, &body)
	if rec.Code != http.StatusOK || body.Profile.Email != a.Email || len(body.Roles) != 2 {
		t.Errorf("export: %d, %s with %d roles; want the account's roles in both organisations", rec.Code, body.Profile.Email, len(body.Roles))
	}
}
