//go:build integration

package abac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestLockOutIsJudgedOnTheAuthorsCall checks that a deny on every action for
// a session without a second factor saves for an author whose session met one
// and is refused for one whose session didn't, as it would lock them out, and
// that a deny on a group saves for an author outside it.
func TestLockOutIsJudgedOnTheAuthorsCall(t *testing.T) {
	organization := dbtest.Organization(t)
	author := dbtest.User(t, organization, organization)
	group(t, organization, "Contractors", nil)
	svc := newService(t)
	save := func(sessionID uuid.UUID, name, condition string) *httptest.ResponseRecorder {
		p := dbtest.Principal(author.ID, organization)
		p.SessionID = &sessionID
		api := dbtest.Serve(p, (&Handler{Service: svc}).Mount)
		return dbtest.Do(t, api, http.MethodPost, "/organizations/"+organization.String()+"/abac/policies", map[string]any{
			"name": name, "effect": "deny", "resource_type": "*", "action": "*", "condition": json.RawMessage(condition), "enabled": true,
		})
	}
	noMFA := `{"attr":"context.mfa","op":"ne","value":true}`
	if rec := save(session(t, author.ID, organization, ""), "deny_without_mfa", noMFA); !strings.Contains(rec.Body.String(), CodePolicyLocksOut) {
		t.Errorf("an author without a second factor saved a deny without one: %d %s", rec.Code, rec.Body.String())
	}
	if rec := save(session(t, author.ID, organization, "mfa"), "deny_without_mfa", noMFA); rec.Code != http.StatusCreated {
		t.Errorf("an author with a second factor saving a deny without one: %d %s", rec.Code, rec.Body.String())
	}
	contractors := `{"attr":"subject.groups","op":"contains","value":"Contractors"}`
	if rec := save(session(t, author.ID, organization, ""), "deny_contractors", contractors); rec.Code != http.StatusCreated {
		t.Errorf("an author outside a group saving a deny on it: %d %s", rec.Code, rec.Body.String())
	}
}
