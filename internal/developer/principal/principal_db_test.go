//go:build integration

package principal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// system is the actor of a test's own calls.
var system = audit.Actor{Type: "system"}

// TestClientCredentialsAuthenticatesThePrincipal checks the client_credentials
// grant against real principals: an id naming none is not the principals' to
// answer, a wrong secret is refused, the right one gets the principal's own
// token, and a disabled principal is refused once its secret checks out.
func TestClientCredentialsAuthenticatesThePrincipal(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := NewService(dbtest.Pool(t), issuer)
	organization := dbtest.Organization(t)
	p, secret, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "Reporting", Scopes: []string{"user.read"}}, system)
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	id := p.ID.String()

	for _, unknown := range []string{uuid.NewString(), "not-a-principal-id", ""} {
		if tok, known, err := svc.ClientCredentials(ctx, unknown, secret); known || err != nil || tok != nil {
			t.Errorf("client id %q: %v, known %v, %v; want it unknown", unknown, tok, known, err)
		}
	}
	if _, known, err := svc.ClientCredentials(ctx, id, "wrong-secret"); !known || !errors.Is(err, errs.ErrPrincipalInvalidCredentials) {
		t.Errorf("a wrong secret: known %v, %v; want %v", known, err, errs.ErrPrincipalInvalidCredentials)
	}
	tok, known, err := svc.ClientCredentials(ctx, id, secret)
	if err != nil || !known || tok.Lifetime != issuer.AccessTTL() || tok.Scope != "user.read" {
		t.Fatalf("the right secret: %+v, known %v, %v; want a token for the access-token lifetime", tok, known, err)
	}
	if claims, err := issuer.VerifyAccess(tok.AccessToken); err != nil || claims.Subject != id || claims.ActorType != "service" ||
		claims.OrganizationID != organization || claims.Scope != "user.read" || claims.AgentID != "" {
		t.Errorf("the token's claims %+v, %v; want the principal's own", claims, err)
	}

	if live, err := svc.PrincipalLive(ctx, p.ID); err != nil || !live {
		t.Errorf("an enabled principal: live %v, %v; want live", live, err)
	}
	if live, err := svc.PrincipalLive(ctx, uuid.New()); err != nil || live {
		t.Errorf("an unknown principal: live %v, %v; want not live", live, err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.service_principals SET disabled_at = NOW() WHERE id = $1 AND organization_id = $2`, p.ID, organization); err != nil {
		t.Fatal(err)
	}
	if _, known, err := svc.ClientCredentials(ctx, id, secret); !known || !errors.Is(err, errs.ErrPrincipalDisabled) {
		t.Errorf("a disabled principal: known %v, %v; want %v", known, err, errs.ErrPrincipalDisabled)
	}
	if _, known, err := svc.ClientCredentials(ctx, id, "wrong-secret"); !known || !errors.Is(err, errs.ErrPrincipalInvalidCredentials) {
		t.Errorf("a disabled principal's wrong secret: known %v, %v; want %v, which tells nothing of its state", known, err, errs.ErrPrincipalInvalidCredentials)
	}
	if live, err := svc.PrincipalLive(ctx, p.ID); err != nil || live {
		t.Errorf("a disabled principal: live %v, %v; want not live", live, err)
	}
}

// TestRotatedSecretsOverlapAndPrincipalsEnable checks that a rotated
// principal's old secret goes on getting tokens until its overlap ends, that a
// token issued is noted as its last use, and that a disabled principal can be
// enabled again.
func TestRotatedSecretsOverlapAndPrincipalsEnable(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	p, oldSecret, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "Reporting", Description: "Nightly export", Scopes: []string{}}, system)
	if err != nil {
		t.Fatal(err)
	}
	if p.Description != "Nightly export" {
		t.Errorf("created description = %q", p.Description)
	}
	newSecret, until, err := svc.RotateSecret(ctx, organization, p.ID, time.Hour, system)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for name, secret := range map[string]string{"old": oldSecret, "new": newSecret} {
		if _, known, err := svc.ClientCredentials(ctx, p.ID.String(), secret); err != nil || !known {
			t.Errorf("the %s secret during the overlap: known %v, %v", name, known, err)
		}
	}
	list, err := svc.List(ctx, organization)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v, %v", list, err)
	}
	if got := list[0]; got.Description != "Nightly export" || got.LastUsedAt == nil ||
		got.PreviousSecretExpiresAt == nil || !got.PreviousSecretExpiresAt.Equal(until.Truncate(time.Microsecond)) {
		t.Errorf("listed principal %+v: want its description, a last use and the overlap's end %s", got, until)
	}
	if _, _, err := svc.RotateSecret(ctx, organization, p.ID, 0, system); err != nil {
		t.Fatalf("rotate with no overlap: %v", err)
	}
	if _, _, err := svc.ClientCredentials(ctx, p.ID.String(), newSecret); !errors.Is(err, errs.ErrPrincipalInvalidCredentials) {
		t.Errorf("a secret rotated with no overlap: %v, want %v", err, errs.ErrPrincipalInvalidCredentials)
	}
	if _, _, err := svc.RotateSecret(ctx, dbtest.Organization(t), p.ID, time.Hour, system); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotate from another organization: %v, want %v", err, ErrNotFound)
	}

	if err := svc.Disable(ctx, organization, p.ID, system); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enable(ctx, dbtest.Organization(t), p.ID, system); !errors.Is(err, ErrNotFound) {
		t.Errorf("enable from another organization: %v, want %v", err, ErrNotFound)
	}
	if err := svc.Enable(ctx, organization, p.ID, system); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if live, err := svc.PrincipalLive(ctx, p.ID); err != nil || !live {
		t.Errorf("an enabled principal: live %v, %v", live, err)
	}
}

// TestClientCredentialsRefusedForDeletedOrganization checks that a service
// principal of a suspended or deleted organization gets no token, its right
// secret included, as if it didn't exist, and that the tokens it was already
// issued stop: it is no longer live. Reactivating the organization restores
// both.
func TestClientCredentialsRefusedForDeletedOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	p, secret, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "Reporting", Scopes: []string{}}, system)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name, change string
		works        bool
	}{
		{"suspended", `UPDATE organization.organizations SET status = 'suspended' WHERE id = $1`, false},
		{"reactivated", `UPDATE organization.organizations SET status = 'active' WHERE id = $1`, true},
		{"deleted", `UPDATE organization.organizations SET deleted_at = NOW() WHERE id = $1`, false},
	} {
		if _, err := pool.Exec(ctx, step.change, organization); err != nil {
			t.Fatal(err)
		}
		if tok, known, err := svc.ClientCredentials(ctx, p.ID.String(), secret); (err == nil && known && tok != nil) != step.works || known != step.works {
			t.Errorf("a token for a principal of a %s organization: known %v, %v; want works=%v", step.name, known, err, step.works)
		}
		if live, err := svc.PrincipalLive(ctx, p.ID); err != nil || live != step.works {
			t.Errorf("an issued token of a %s organization's principal: live %v, %v; want %v", step.name, live, err, step.works)
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

// TestPrincipalChangesCommitWithTheirAudit checks that creating and disabling
// a service principal over HTTP is audited as the caller's, who is noted as
// its creator, and that either is refused and rolled back when its audit row
// can't be written.
func TestPrincipalChangesCommitWithTheirAudit(t *testing.T) {
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	grantAll := func(context.Context, *httpx.Principal, uuid.UUID, []string) error { return nil }
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc, GrantCheck: grantAll}).Mount)
	create := func(name string) (uuid.UUID, int) {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodPost, "/service-principals", map[string]any{"name": name, "scopes": []string{"user.read"}})
		var out struct {
			ClientID uuid.UUID `json:"client_id"`
		}
		if rec.Code == http.StatusCreated {
			dbtest.Decode(t, rec, &out)
		}
		return out.ClientID, rec.Code
	}
	audited := func(action string, id uuid.UUID) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2
			AND resource_type = 'service_principal' AND resource_id = $3 AND actor_user_id = $4`, organization, action, id, admin.ID)
	}

	first, code := create("Reporting")
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	second, _ := create("Export")
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.service_principals WHERE id = $1 AND organization_id = $2 AND created_by = $3`,
		first, organization, admin.ID); n != 1 || audited("service_principal.created", first) != 1 {
		t.Errorf("a created principal: creator noted %d, audited %d; want both", n, audited("service_principal.created", first))
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, "/service-principals/"+first.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if n := audited("service_principal.disabled", first); n != 1 {
		t.Errorf("a disabled principal: %d audit rows, want 1", n)
	}

	refuseAudit(t, organization, "service_principal.created")
	refuseAudit(t, organization, "service_principal.disabled")
	if _, code := create("Blocked"); code != http.StatusInternalServerError {
		t.Errorf("create with its audit refused: %d, want 500", code)
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, "/service-principals/"+second.String(), nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("disable with its audit refused: %d, want 500", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.service_principals WHERE organization_id = $1 AND name = 'Blocked'`, organization); n != 0 {
		t.Error("a principal whose creation wasn't audited was kept")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.service_principals WHERE id = $1 AND organization_id = $2 AND disabled_at IS NULL`,
		second, organization); n != 1 {
		t.Error("a principal whose disabling wasn't audited was disabled")
	}
}

// TestServicePrincipalsCarryOnlyTheCreatorsAuthority checks that a credential is created
// only with scopes its creator holds: a developer can't mint one with role.write.
func TestServicePrincipalsCarryOnlyTheCreatorsAuthority(t *testing.T) {
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	dbtest.Assign(t, developer.ID, organization, dbtest.Role(t, organization, "apikey.write", "user.read"))
	h := dbtest.Serve(dbtest.Principal(developer.ID, organization),
		(&Handler{Service: NewService(pool, dbtest.Issuer(t)), GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	path := "/service-principals"

	body := func(scopes ...string) map[string]any {
		return map[string]any{"name": "ci-deploy", "scopes": scopes}
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read", "role.write")); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), errs.CodeRBACGrantExceedsCaller) || !strings.Contains(rec.Body.String(), "role.write") {
		t.Errorf("create with role.write: %d %s, want 403 %s naming role.write", rec.Code, rec.Body.String(), errs.CodeRBACGrantExceedsCaller)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read")); rec.Code != http.StatusCreated {
		t.Errorf("create with the creator's own scope: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.service_principals WHERE organization_id = $1`, organization); n != 1 {
		t.Errorf("%d credentials stored, want only the permitted one", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.service_principals WHERE organization_id = $1 AND created_by = $2`, organization, developer.ID); n != 1 {
		t.Error("the credential doesn't record who created it")
	}
}
