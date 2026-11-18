//go:build integration

package ldap

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// testCipher seals what the tests store.
func testCipher(t *testing.T) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// TestDirectoryConnectionsOverHTTP checks that an organization manages its
// directory connections without the service password ever being returned,
// tests them, and that people sign in through one, provisioned into that
// organization only, until it is disabled.
func TestDirectoryConnectionsOverHTTP(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	admin := dbtest.User(t, organization, organization)
	outsider := dbtest.UserAt(t, dbtest.Unique("eve")+"@"+domain, other, other)
	dir := &directory{
		binds: map[string]string{
			"cn=service,dc=example,dc=test": "service-secret",
			"uid=bob,dc=example,dc=test":    "bob-secret",
			"uid=eve,dc=example,dc=test":    "eve-secret",
			"uid=nomail,dc=example,dc=test": "nomail-secret",
		},
		entries: map[string]dirEntry{
			"bob":    {dn: "uid=bob,dc=example,dc=test", attrs: map[string]string{"mail": dbtest.Unique("bob") + "@" + domain, "cn": "Bob"}},
			"eve":    {dn: "uid=eve,dc=example,dc=test", attrs: map[string]string{"mail": outsider.Email, "cn": "Eve"}},
			"nomail": {dn: "uid=nomail,dc=example,dc=test", attrs: map[string]string{"cn": "No Mail"}},
		},
	}
	serverURL := dir.start(t)
	svc := directoryService(t)
	observed := &operations{}
	svc.SetOperationObserver(observed)
	h := &Handler{Service: svc}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	public := chi.NewRouter()
	h.MountPublic(public)
	base := "/organizations/" + organization.String() + "/ldap"

	connection := map[string]any{
		"name": "Directory", "server_url": serverURL, "bind_dn": "cn=service,dc=example,dc=test",
		"bind_password": "service-secret", "base_dn": "dc=example,dc=test", "status": "active",
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, connection)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "service-secret") || conn.UserFilter != "(uid=%s)" || conn.EmailAttribute != "mail" {
		t.Fatalf("create: %d %s; want the defaults and no password", rec.Code, rec.Body.String())
	}
	for name, change := range map[string]map[string]any{
		CodeConnectionFieldsRequired: {"bind_password": ""},
		CodeServerURLInvalid:         {"server_url": "https://directory.example.test"},
		CodeTLSVerifyRequired:        {"skip_tls_verify": true},
	} {
		bad := map[string]any{}
		for k, v := range connection {
			bad[k] = v
		}
		for k, v := range change {
			bad[k] = v
		}
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, bad); !strings.Contains(rec.Body.String(), name) {
			t.Errorf("create with %v: %d %s, want %s", change, rec.Code, rec.Body.String(), name)
		}
	}
	connPath := base + "/" + conn.ID.String()
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, connPath+"/test", nil); rec.Code != http.StatusOK {
		t.Errorf("test the connection: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, connPath, map[string]string{"bind_password": "stale"}); rec.Code != http.StatusOK {
		t.Fatalf("change the service password: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, connPath+"/test", nil); !strings.Contains(rec.Body.String(), CodeServiceBindFailed) {
		t.Errorf("test with a wrong service password: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, connPath, map[string]string{"bind_password": "service-secret", "name": "Head office"}); !strings.Contains(rec.Body.String(), `"Head office"`) {
		t.Errorf("rename: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, connPath, map[string]string{"status": "retired"}); !strings.Contains(rec.Body.String(), CodeStatusInvalid) {
		t.Errorf("an unknown status: %d %s", rec.Code, rec.Body.String())
	}
	observed.mu.Lock()
	// The refused service account is recorded as the directory refusing (403),
	// not as unreachable.
	if got := strings.Join(observed.got, ","); got != "test OK,test Forbidden" {
		t.Errorf("operations recorded %q", got)
	}
	// The failure keeps its own code and the server it reached.
	if len(observed.ops) == 2 && (observed.ops[1].Reason != CodeServiceBindFailed || observed.ops[1].Params["host"] == "" || observed.ops[0].Reason != "") {
		t.Errorf("a refused test recorded as %+v, a passing one as %+v; want the refusal's code and the host", observed.ops[1], observed.ops[0])
	}
	observed.mu.Unlock()

	signIn := func(username, password string) response {
		rec := dbtest.Do(t, public, http.MethodPost, "/ldap/"+conn.ID.String()+"/authenticate", map[string]string{"username": username, "password": password})
		return response{rec.Code, rec.Body.String()}
	}
	first := signIn("bob", "bob-secret")
	if first.code != http.StatusOK || !strings.Contains(first.body, `"access_token"`) {
		t.Fatalf("first sign-in: %d %s", first.code, first.body)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1 AND organization_id = $2 AND display_name = 'Bob'`, dir.entries["bob"].attrs["mail"], organization); n != 1 {
		t.Errorf("%d accounts provisioned for bob in the organization, want 1", n)
	}
	if again := signIn("bob", "bob-secret"); again.code != http.StatusOK || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, dir.entries["bob"].attrs["mail"]) != 1 {
		t.Errorf("second sign-in: %d %s", again.code, again.body)
	}
	if res := signIn("eve", "eve-secret"); !strings.Contains(res.body, CodeAccountNotInOrganization) {
		t.Errorf("a directory entry naming another organization's account: %d %s", res.code, res.body)
	}
	if res := signIn("nomail", "nomail-secret"); !strings.Contains(res.body, CodeEmailAttributeMissing) {
		t.Errorf("an entry without an address: %d %s", res.code, res.body)
	}
	if res := signIn("bob", ""); !strings.Contains(res.body, CodeCredentialsRequired) {
		t.Errorf("no password: %d %s", res.code, res.body)
	}
	// Each sign-in names the login name tried, and the person once known.
	observed.mu.Lock()
	var bobs, nomail int
	for _, op := range observed.ops {
		switch {
		case op.Operation == "sign-in" && op.Subject == "bob" && op.UserID != nil && op.Reason == "":
			bobs++
		case op.Operation == "sign-in" && op.Subject == "nomail" && op.UserID == nil && op.Reason == CodeEmailAttributeMissing:
			nomail++
		}
	}
	observed.mu.Unlock()
	if bobs != 2 || nomail != 1 {
		t.Errorf("sign-ins recorded %d times for bob with the person, %d for nomail with its reason; want 2 and 1", bobs, nomail)
	}

	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	otherPath := "/organizations/" + other.String() + "/ldap/" + conn.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]string{"name": "Taken"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organization %s on the connection: %d, want 404", method, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, otherPath+"/test", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization testing the connection: %d, want 404", rec.Code)
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, connPath, map[string]string{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	if res := signIn("bob", "bob-secret"); !strings.Contains(res.body, CodeConnectionDisabled) {
		t.Errorf("sign in through a disabled connection: %d %s", res.code, res.body)
	}
	var list struct {
		Items []Connection `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, base, nil), &list)
	if len(list.Items) != 1 || list.Items[0].LastLoginAt == nil || list.Items[0].Status != "disabled" {
		t.Errorf("connections %+v; want the one, disabled, with its last sign-in", list.Items)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, connPath, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action LIKE 'ldap.connection_%'`, organization); n != 5 {
		t.Errorf("%d connection changes recorded, want created, three updates and deleted", n)
	}
}

// response is a response's status and body.
type response struct {
	code int
	body string
}

// TestLDAPTrustChangeMustOutrankLinkedAdministrators checks that pointing a
// directory connection an owner is linked to at another server, or at other
// entries of its directory, is refused to someone who can change connections
// but doesn't outrank the owner, as it could then sign in as them, while
// renaming it isn't.
func TestLDAPTrustChangeMustOutrankLinkedAdministrators(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	h := &Handler{Service: directoryService(t), ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, editor := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "connection.write", "connection.read"))
	base := "/organizations/" + organization.String() + "/ldap"
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(owner.ID, organization), h.Mount), http.MethodPost, base, map[string]any{
		"name": "Directory", "server_url": "ldap://directory.example.test", "bind_dn": "cn=service,dc=example,dc=test",
		"bind_password": "service-secret", "base_dn": "dc=example,dc=test", "status": "active",
	})
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject) VALUES ($1, $2, 'ldap', $3, 'uid=owner')`,
		owner.ID, organization, conn.ID); err != nil {
		t.Fatal(err)
	}
	asEditor := dbtest.Serve(dbtest.Principal(editor.ID, organization), h.Mount)

	for name, body := range map[string]map[string]any{
		"server":      {"server_url": "ldap://directory.attacker.example"},
		"base DN":     {"base_dn": "ou=people,dc=example,dc=test"},
		"user filter": {"user_filter": "(mail=%s)"},
	} {
		if rec := dbtest.Do(t, asEditor, http.MethodPatch, base+"/"+conn.ID.String(), body); rec.Code != http.StatusForbidden ||
			!strings.Contains(rec.Body.String(), errs.CodeRBACTrustChangeOutranks) {
			t.Errorf("an editor changes the %s of a connection an owner is linked to: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), errs.CodeRBACTrustChangeOutranks)
		}
	}
	if rec := dbtest.Do(t, asEditor, http.MethodPatch, base+"/"+conn.ID.String(), map[string]any{"name": "Directory (EU)"}); rec.Code != http.StatusOK {
		t.Errorf("an editor renames it: %d %s, want 200", rec.Code, rec.Body.String())
	}
}
