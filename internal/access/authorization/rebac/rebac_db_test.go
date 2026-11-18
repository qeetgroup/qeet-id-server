//go:build integration

package rebac

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newHandler returns the relationship routes' handler, deciding checks across
// roles, relationships and attribute policies as the server does.
func newHandler(t *testing.T) *Handler {
	t.Helper()
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	policies, err := abac.NewService(pool, allPlans{}, svc.Check)
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{Service: svc, Decider: decide.New(rbac.NewRepository(pool), svc, policies)}
}

// allPlans is a plan gate that allows every feature.
type allPlans struct{}

func (allPlans) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// writeTuple stores the tuple object#relation@subject through h's write route.
func writeTuple(t *testing.T, h http.Handler, organization uuid.UUID, object, relation, subject string) Tuple {
	t.Helper()
	rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/relation-tuples",
		map[string]string{"object": object, "relation": relation, "subject": subject})
	if rec.Code != http.StatusCreated {
		t.Fatalf("write %s#%s@%s: %d %s", object, relation, subject, rec.Code, rec.Body.String())
	}
	var out Tuple
	dbtest.Decode(t, rec, &out)
	return out
}

// checkResult is the check route's answer when asked to explain itself.
type checkResult struct {
	Allowed   bool           `json:"allowed"`
	DecidedBy map[string]any `json:"decided_by"`
	Path      []ExplainStep  `json:"path"`
}

// ask asks h's check route, with an explanation, whether user holds relation
// on object.
func ask(t *testing.T, h http.Handler, organization uuid.UUID, object, relation, user string) checkResult {
	t.Helper()
	rec := dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/relation-tuples/check?explain=true",
		map[string]string{"object": object, "relation": relation, "user_id": user})
	if rec.Code != http.StatusOK {
		t.Fatalf("check %s#%s for %s: %d %s", object, relation, user, rec.Code, rec.Body.String())
	}
	var out checkResult
	dbtest.Decode(t, rec, &out)
	return out
}
