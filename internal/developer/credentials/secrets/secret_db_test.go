//go:build integration

package secret

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestSecretsStayInTheirOrganization checks that one organization can neither reveal nor
// change another organization's secret, and that a vault read by name finds only its
// own secret of that name.
func TestSecretsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), testService(t, 7).box)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminB := dbtest.User(t, organizationB, organizationB)
	secretA, err := svc.Create(ctx, organizationA, "stripe", "", "sk_live_tenant_a", nil)
	if err != nil {
		t.Fatalf("create secret in A: %v", err)
	}

	principal := dbtest.Principal(adminB.ID, organizationB)
	principal.Scopes = []string{"vault:read"}
	asB := dbtest.Serve(principal, (&Handler{Service: svc}).Mount)
	inB := "/tenants/" + organizationB.String() + "/secrets/" + secretA.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPost, inB + "/reveal", nil, http.StatusNotFound},
		{http.MethodPatch, inB, map[string]any{"value": "sk_live_tenant_b"}, http.StatusNotFound},
		{http.MethodPatch, inB, map[string]any{"scope": "agents"}, http.StatusNotFound},
		{http.MethodDelete, inB, nil, http.StatusNotFound},
		{http.MethodGet, "/vault/stripe", nil, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + organizationA.String() + "/secrets", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+organizationB.String()+"/secrets", nil)); slices.Contains(ids, secretA.ID) {
		t.Error("tenant B's secret list includes tenant A's")
	}

	if _, err := svc.Create(ctx, organizationB, "stripe", "", "sk_live_tenant_b", nil); err != nil {
		t.Fatalf("create secret in B: %v", err)
	}
	var vault struct {
		Value string `json:"value"`
	}
	dbtest.Decode(t, dbtest.Do(t, asB, http.MethodGet, "/vault/stripe", nil), &vault)
	if vault.Value != "sk_live_tenant_b" {
		t.Errorf("tenant B's vault read returned %q, want its own secret", vault.Value)
	}
	if _, value, err := svc.Reveal(ctx, organizationA, secretA.ID); err != nil || value != "sk_live_tenant_a" {
		t.Errorf("tenant A's secret after tenant B's calls: %q, %v", value, err)
	}
}

// TestSecretListIsCapped checks that an organization with more secrets than one list
// answers holds gets the first paging.MaxListItems of them, marked truncated.
func TestSecretListIsCapped(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), testService(t, 7).box)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO organization.secrets (organization_id, name, ciphertext, nonce)
		SELECT $1, 'secret-' || n, '\x00', '\x00' FROM generate_series(1, $2::int) AS n
	`, organization, paging.MaxListItems+1); err != nil {
		t.Fatal(err)
	}
	principal := dbtest.Principal(admin.ID, organization)
	principal.Scopes = []string{"vault:read"}
	rec := dbtest.Do(t, dbtest.Serve(principal, (&Handler{Service: svc}).Mount), http.MethodGet, "/tenants/"+organization.String()+"/secrets", nil)
	var body struct {
		Items     []json.RawMessage `json:"items"`
		Truncated bool              `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list: %d %v", rec.Code, err)
	}
	if len(body.Items) != paging.MaxListItems || !body.Truncated {
		t.Errorf("list of %d secrets: %d items, truncated %v; want %d, true", paging.MaxListItems+1, len(body.Items), body.Truncated, paging.MaxListItems)
	}
}

// TestSecretRevealAndRotation checks that a reveal notes the person, or the
// machine credential, on the secret, and that a rotation interval makes the
// secret due that long after its value last changed: a scope change leaves the
// due date, a new value moves it, and null removes the interval.
func TestSecretRevealAndRotation(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), testService(t, 7).box)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/tenants/" + organization.String() + "/secrets"

	decode := func(code int, body []byte, want int) Secret {
		t.Helper()
		var sec Secret
		if code != want {
			t.Fatalf("status %d, want %d: %s", code, want, body)
		}
		if err := json.Unmarshal(body, &sec); err != nil {
			t.Fatal(err)
		}
		return sec
	}
	listed := func() Secret {
		t.Helper()
		rec := dbtest.Do(t, asAdmin, http.MethodGet, base, nil)
		var body struct{ Items []Secret }
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Items) != 1 {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		return body.Items[0]
	}

	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": "stripe", "scope": "payments", "value": "sk_live_abcdefgh", "rotation_interval_days": 30})
	sec := decode(rec.Code, rec.Body.Bytes(), http.StatusCreated)
	if sec.RotationIntervalDays == nil || *sec.RotationIntervalDays != 30 || sec.RotationDueAt == nil ||
		!sec.RotationDueAt.Equal(sec.ValueChangedAt.AddDate(0, 0, 30)) || sec.RotationOverdue || sec.LastRevealedAt != nil {
		t.Fatalf("created: %+v", sec)
	}
	item := base + "/" + sec.ID.String()

	if rec := dbtest.Do(t, asAdmin, http.MethodPost, item+"/reveal", nil); rec.Code != http.StatusOK {
		t.Fatalf("reveal: %d %s", rec.Code, rec.Body.String())
	}
	got := listed()
	if got.LastRevealedAt == nil || got.LastRevealedBy == nil || got.LastRevealedBy.ID != admin.ID ||
		got.LastRevealedBy.Email != admin.Email || got.LastRevealedCredential != "" {
		t.Errorf("after a person's reveal: %+v, by %+v", got, got.LastRevealedBy)
	}

	key := &httpx.Principal{UserID: &admin.ID, OrganizationID: &organization, ActorType: "api_key", Subject: "key-1234"}
	if rec := dbtest.Do(t, dbtest.Serve(key, (&Handler{Service: svc}).Mount), http.MethodPost, item+"/reveal", nil); rec.Code != http.StatusOK {
		t.Fatalf("reveal with a key: %d %s", rec.Code, rec.Body.String())
	}
	if got := listed(); got.LastRevealedBy != nil || got.LastRevealedCredential != "key-1234" {
		t.Errorf("after a key's reveal: by %+v, credential %q; want the key", got.LastRevealedBy, got.LastRevealedCredential)
	}

	long := time.Now().Add(-40 * 24 * time.Hour)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.secrets SET value_changed_at = $3 WHERE id = $1 AND organization_id = $2`, sec.ID, organization, long); err != nil {
		t.Fatal(err)
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, item, map[string]any{"scope": "billing"})
	if sec := decode(rec.Code, rec.Body.Bytes(), http.StatusOK); !sec.RotationOverdue || sec.Scope != "billing" ||
		sec.RotationIntervalDays == nil || *sec.RotationIntervalDays != 30 || sec.ValueChangedAt.After(long.Add(time.Second)) {
		t.Errorf("a scope change 40 days after the value: %+v; want it still overdue", sec)
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, item, map[string]any{"value": "sk_live_ijklmnop"})
	if sec := decode(rec.Code, rec.Body.Bytes(), http.StatusOK); sec.RotationOverdue || !sec.ValueChangedAt.After(long.Add(time.Hour)) {
		t.Errorf("after a new value: %+v; want due again in 30 days", sec)
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, item, map[string]any{"rotation_interval_days": nil})
	if sec := decode(rec.Code, rec.Body.Bytes(), http.StatusOK); sec.RotationIntervalDays != nil || sec.RotationDueAt != nil || sec.RotationOverdue {
		t.Errorf("after removing the interval: %+v", sec)
	}
	for _, days := range []int{0, 3651} {
		rec := dbtest.Do(t, asAdmin, http.MethodPatch, item, map[string]any{"rotation_interval_days": days})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "secret.rotation_interval_out_of_range") {
			t.Errorf("an interval of %d days: %d %s, want 422", days, rec.Code, rec.Body.String())
		}
	}
}
