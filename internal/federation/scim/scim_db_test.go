//go:build integration

package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// planGate includes SCIM in the plans of the organizations it holds.
type planGate map[uuid.UUID]bool

func (g planGate) FeatureAllowed(_ context.Context, organizationID uuid.UUID, _ string) (bool, error) {
	return g[organizationID], nil
}

// TestLapsedPlanStopsSCIM checks that a SCIM token issued while the plan
// included SCIM provisions nothing once the plan has lapsed.
func TestLapsedPlanStopsSCIM(t *testing.T) {
	ctx := dbtest.Context(t)
	plans := planGate{}
	f := newSCIMFixture(t, ctx, func(d *Deps) { d.Gate = plans })
	plans[f.organizationID] = true
	if rec := f.do(t, http.MethodGet, "/scim/v2/Users", nil); rec.Code != http.StatusOK {
		t.Fatalf("SCIM on a plan with it: status %d", rec.Code)
	}

	delete(plans, f.organizationID) // the plan lapses
	rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": dbtest.Unique("new") + "@example.test",
	})
	if rec.Code != http.StatusForbidden || decodeBody(t, rec)["schemas"] == nil {
		t.Errorf("SCIM after the plan lapsed: status %d %s, want a SCIM 403", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE organization_id = $1`, f.organizationID); n != 0 {
		t.Errorf("%d users provisioned after the plan lapsed, want none", n)
	}
}

func TestMain(m *testing.M) { dbtest.Main(m) }

// scimFixture sets up an organization, a SCIM bearer token, two users, and a mounted
// SCIM router driving the real handlers.
type scimFixture struct {
	organizationID uuid.UUID
	token          string
	router         chi.Router
	svc            *Service
}

func newSCIMFixture(t *testing.T, ctx context.Context, with ...func(*Deps)) *scimFixture {
	t.Helper()
	tid := dbtest.Organization(t)

	// Seed a SCIM bearer token for this organization (hash scheme matches Rotate).
	token := tokenPrefix + uuid.NewString()
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO organization.scim_tokens (organization_id, token_hash, token_prefix)
		VALUES ($1, $2, $3)
	`, tid, codes.Hash(token), tokenPrefix+"seed"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	svc := newTestService(t, dbtest.Pool(t), with...)
	h := &Handler{Service: svc}
	r := chi.NewRouter()
	h.MountPublic(r)
	return &scimFixture{organizationID: tid, token: token, router: r, svc: svc}
}

// seedUser creates an organization user and returns its id.
func (f *scimFixture) seedUser(t *testing.T, ctx context.Context, email string) uuid.UUID {
	t.Helper()
	repo := user.NewRepository(dbtest.Pool(t))
	u, err := repo.CreateWithCredential(ctx, user.CreateInput{OrganizationID: f.organizationID, Email: email}, "")
	if err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return u.ID
}

// do issues a SCIM request and returns the recorder.
func (f *scimFixture) do(t *testing.T, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "http://localhost:4000"+path, rdr)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", scimContentType)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body (%d): %v\nbody=%s", rec.Code, err, rec.Body.String())
	}
	return m
}

const schemaPatchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
