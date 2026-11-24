//go:build integration

package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// system is the actor of a test's own calls.
var system = audit.Actor{Type: "system"}

// TestSecretsStayInTheirOrganization checks that one organization can neither reveal nor
// change another organization's secret, and that a vault read by name finds only its
// own secret of that name.
func TestSecretsStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), testService(t, 7).box)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminB := dbtest.User(t, organizationB, organizationB)
	secretA, err := svc.Create(ctx, organizationA, "stripe", "", "sk_live_organization_a", nil, Caller{Actor: system})
	if err != nil {
		t.Fatalf("create secret in A: %v", err)
	}

	principal := dbtest.Principal(adminB.ID, organizationB)
	principal.Scopes = []string{"vault:read"}
	asB := dbtest.Serve(principal, (&Handler{Service: svc}).Mount)
	inB := "/organizations/" + organizationB.String() + "/secrets/" + secretA.ID.String()
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPost, inB + "/reveal", nil, http.StatusNotFound},
		{http.MethodPatch, inB, map[string]any{"value": "sk_live_organization_b"}, http.StatusNotFound},
		{http.MethodPatch, inB, map[string]any{"scope": "agents"}, http.StatusNotFound},
		{http.MethodDelete, inB, nil, http.StatusNotFound},
		{http.MethodGet, "/vault/stripe", nil, http.StatusNotFound},
		{http.MethodGet, "/organizations/" + organizationA.String() + "/secrets", nil, http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("organization B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/organizations/"+organizationB.String()+"/secrets", nil)); slices.Contains(ids, secretA.ID) {
		t.Error("organization B's secret list includes organization A's")
	}

	if _, err := svc.Create(ctx, organizationB, "stripe", "", "sk_live_organization_b", nil, Caller{Actor: system}); err != nil {
		t.Fatalf("create secret in B: %v", err)
	}
	var vault struct {
		Value string `json:"value"`
	}
	dbtest.Decode(t, dbtest.Do(t, asB, http.MethodGet, "/vault/stripe", nil), &vault)
	if vault.Value != "sk_live_organization_b" {
		t.Errorf("organization B's vault read returned %q, want its own secret", vault.Value)
	}
	if _, value, err := svc.Reveal(ctx, organizationA, secretA.ID, Caller{Actor: system}); err != nil || value != "sk_live_organization_a" {
		t.Errorf("organization A's secret after organization B's calls: %q, %v", value, err)
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
	rec := dbtest.Do(t, dbtest.Serve(principal, (&Handler{Service: svc}).Mount), http.MethodGet, "/organizations/"+organization.String()+"/secrets", nil)
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
	base := "/organizations/" + organization.String() + "/secrets"

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

// refuseAudit makes the database refuse organization's audit rows of action
// until t ends, as a failing audit write would.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	ctx, owner := dbtest.Context(t), dbtest.Owner(t)
	name := "refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, sql := range []string{
		`CREATE FUNCTION audit.` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$`,
		fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON audit.events FOR EACH ROW
			WHEN (NEW.organization_id = '%s' AND NEW.action = '%s') EXECUTE FUNCTION audit.%s()`, name, organization, action, name),
	} {
		if _, err := owner.Exec(ctx, sql); err != nil {
			t.Fatalf("refuse %s: %v", action, err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit.events; DROP FUNCTION audit.`+name+`()`)
	})
}

// TestSecretUseIsAuditedOrRefused checks that each change, reveal and vault
// read of a secret is audited as the caller's, a machine credential by its own
// id, and that one whose audit row can't be written is refused: a change is
// rolled back and no value is returned.
func TestSecretUseIsAuditedOrRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), testService(t, 7).box)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	person := dbtest.Principal(admin.ID, organization)
	person.Scopes = []string{"vault:read"}
	asAdmin := dbtest.Serve(person, (&Handler{Service: svc}).Mount)
	key := &httpx.Principal{UserID: &admin.ID, OrganizationID: &organization, ActorType: "api_key", Subject: "key-5678", Scopes: []string{"vault:stripe"}}
	asKey := dbtest.Serve(key, (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/secrets"
	audited := func(action string, id uuid.UUID) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND resource_type = 'secret' AND resource_id = $3 AND actor_user_id = $4`,
			organization, action, id, admin.ID)
	}

	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": "stripe", "value": "sk_live_abcdefgh"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var sec Secret
	dbtest.Decode(t, rec, &sec)
	item := base + "/" + sec.ID.String()
	for _, step := range []struct {
		method, path, action string
		body                 any
	}{
		{http.MethodPatch, item, "secret.rotated", map[string]any{"value": "sk_live_ijklmnop"}},
		{http.MethodPatch, item, "secret.updated", map[string]any{"scope": "billing"}},
		{http.MethodPost, item + "/reveal", "secret.revealed", nil},
		{http.MethodGet, "/vault/stripe", "vault.accessed", nil},
	} {
		if rec := dbtest.Do(t, asAdmin, step.method, step.path, step.body); rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", step.method, step.path, rec.Code, rec.Body.String())
		}
	}
	for _, action := range []string{"secret.created", "secret.rotated", "secret.updated", "secret.revealed", "vault.accessed"} {
		if n := audited(action, sec.ID); n != 1 {
			t.Errorf("%s: %d audit rows as the person, want 1", action, n)
		}
	}
	if rec := dbtest.Do(t, asKey, http.MethodGet, "/vault/stripe", nil); rec.Code != http.StatusOK {
		t.Fatalf("vault read with a key: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'vault.accessed'
		AND actor_type = 'api_key' AND metadata->>'credential_id' = 'key-5678'`, organization); n != 1 {
		t.Errorf("a key's vault read: %d audit rows naming the key, want 1", n)
	}

	for _, action := range []string{"secret.created", "secret.rotated", "secret.updated", "secret.revealed", "vault.accessed", "secret.deleted"} {
		refuseAudit(t, organization, action)
	}
	revealedAt := func() time.Time {
		t.Helper()
		var at time.Time
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT last_revealed_at FROM organization.secrets WHERE id = $1 AND organization_id = $2`,
			sec.ID, organization).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := revealedAt()
	for _, step := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, base, map[string]any{"name": "github", "value": "ghp_abcdefgh"}},
		{http.MethodPatch, item, map[string]any{"value": "sk_live_qrstuvwx"}},
		{http.MethodPatch, item, map[string]any{"scope": "ops"}},
		{http.MethodPost, item + "/reveal", nil},
		{http.MethodGet, "/vault/stripe", nil},
		{http.MethodDelete, item, nil},
	} {
		rec := dbtest.Do(t, asAdmin, step.method, step.path, step.body)
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "sk_live") {
			t.Errorf("%s %s with its audit refused: %d %s; want refused with no value", step.method, step.path, rec.Code, rec.Body.String())
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.secrets WHERE organization_id = $1 AND name = 'github'`, organization); n != 0 {
		t.Error("a secret whose creation wasn't audited was kept")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.secrets WHERE id = $1 AND organization_id = $2 AND last4 = 'mnop' AND scope = 'billing'`,
		sec.ID, organization); n != 1 {
		t.Error("a change that wasn't audited was kept, or a delete that wasn't removed the secret")
	}
	if !revealedAt().Equal(before) {
		t.Error("a reveal that wasn't audited was noted on the secret")
	}
}
