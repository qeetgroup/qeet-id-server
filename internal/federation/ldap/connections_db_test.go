//go:build integration

package ldap

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// operations records each directory operation as "operation status".
type operations struct {
	mu  sync.Mutex
	got []string
	ops []Operation
}

func (o *operations) RecordLDAPOperation(_ context.Context, op Operation) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, op.Operation+" "+http.StatusText(op.Status))
	o.ops = append(o.ops, op)
	return nil
}

// noLDAP is a plan without directory sign-in.
type noLDAP struct{}

func (noLDAP) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return false, nil }

// directoryService returns the LDAP service, allowed to reach loopback directories.
func directoryService(t *testing.T) *Service {
	t.Helper()
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(noFactors{})
	return serviceOver(t, authSvc)
}

// serviceOver returns the LDAP service signing people in through authSvc,
// allowed to reach loopback directories and able to open what the tests seal.
func serviceOver(t *testing.T, authSvc *auth.Service) *Service {
	t.Helper()
	svc := NewService(dbtest.Pool(t), authSvc, egress.DevelopmentPolicy())
	svc.SetCipher(testCipher(t))
	return svc
}

// testCipher seals what the tests store.
func testCipher(t *testing.T) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// storedConnection stores an active directory connection of tenant at
// serverURL, whose service account bindDN binds with "service-secret".
func storedConnection(t *testing.T, tenant uuid.UUID, serverURL, bindDN string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	ct, nonce, err := testCipher(t).Seal(tenant, "ldap-bind", id.String(), []byte("service-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO tenant.ldap_connections
		    (id, tenant_id, name, server_url, bind_dn, bind_password_ct, bind_password_nonce, base_dn, status)
		VALUES ($1, $2, 'Directory', $3, $4, $5, $6, 'dc=example,dc=test', 'active')
	`, id, tenant, serverURL, bindDN, ct, nonce); err != nil {
		t.Fatalf("connection: %v", err)
	}
	return id
}

// TestDirectoryConnectionsOverHTTP checks that an organisation manages its
// directory connections without the service password ever being returned,
// tests them, and that people sign in through one, provisioned into that
// organisation only, until it is disabled.
func TestDirectoryConnectionsOverHTTP(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	domain := dbtest.Domain(t, tenant)
	admin := dbtest.User(t, tenant, tenant)
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
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	public := chi.NewRouter()
	h.MountPublic(public)
	base := "/tenants/" + tenant.String() + "/ldap"

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
		errs.CodeLDAPConnectionFieldsRequired: {"bind_password": ""},
		errs.CodeLDAPServerURLInvalid:         {"server_url": "https://directory.example.test"},
		errs.CodeLDAPTLSVerifyRequired:        {"skip_tls_verify": true},
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
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, connPath+"/test", nil); !strings.Contains(rec.Body.String(), errs.CodeLDAPServiceBindFailed) {
		t.Errorf("test with a wrong service password: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, connPath, map[string]string{"bind_password": "service-secret", "name": "Head office"}); !strings.Contains(rec.Body.String(), `"Head office"`) {
		t.Errorf("rename: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, connPath, map[string]string{"status": "retired"}); !strings.Contains(rec.Body.String(), errs.CodeLDAPStatusInvalid) {
		t.Errorf("an unknown status: %d %s", rec.Code, rec.Body.String())
	}
	observed.mu.Lock()
	// The refused service account is recorded as the directory refusing (403),
	// not as unreachable.
	if got := strings.Join(observed.got, ","); got != "test OK,test Forbidden" {
		t.Errorf("operations recorded %q", got)
	}
	// The failure keeps its own code and the server it reached.
	if len(observed.ops) == 2 && (observed.ops[1].Reason != errs.CodeLDAPServiceBindFailed || observed.ops[1].Params["host"] == "" || observed.ops[0].Reason != "") {
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
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1 AND tenant_id = $2 AND display_name = 'Bob'`, dir.entries["bob"].attrs["mail"], tenant); n != 1 {
		t.Errorf("%d accounts provisioned for bob in the organisation, want 1", n)
	}
	if again := signIn("bob", "bob-secret"); again.code != http.StatusOK || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, dir.entries["bob"].attrs["mail"]) != 1 {
		t.Errorf("second sign-in: %d %s", again.code, again.body)
	}
	if res := signIn("eve", "eve-secret"); !strings.Contains(res.body, errs.CodeLDAPAccountNotInTenant) {
		t.Errorf("a directory entry naming another organisation's account: %d %s", res.code, res.body)
	}
	if res := signIn("nomail", "nomail-secret"); !strings.Contains(res.body, errs.CodeLDAPEmailAttributeMissing) {
		t.Errorf("an entry without an address: %d %s", res.code, res.body)
	}
	if res := signIn("bob", ""); !strings.Contains(res.body, errs.CodeLDAPCredentialsRequired) {
		t.Errorf("no password: %d %s", res.code, res.body)
	}
	// Each sign-in names the login name tried, and the person once known.
	observed.mu.Lock()
	var bobs, nomail int
	for _, op := range observed.ops {
		switch {
		case op.Operation == "sign-in" && op.Subject == "bob" && op.UserID != nil && op.Reason == "":
			bobs++
		case op.Operation == "sign-in" && op.Subject == "nomail" && op.UserID == nil && op.Reason == errs.CodeLDAPEmailAttributeMissing:
			nomail++
		}
	}
	observed.mu.Unlock()
	if bobs != 2 || nomail != 1 {
		t.Errorf("sign-ins recorded %d times for bob with the person, %d for nomail with its reason; want 2 and 1", bobs, nomail)
	}

	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	otherPath := "/tenants/" + other.String() + "/ldap/" + conn.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]string{"name": "Taken"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organisation %s on the connection: %d, want 404", method, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, otherPath+"/test", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation testing the connection: %d, want 404", rec.Code)
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, connPath, map[string]string{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	if res := signIn("bob", "bob-secret"); !strings.Contains(res.body, errs.CodeLDAPConnectionDisabled) {
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
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action LIKE 'ldap.connection_%'`, tenant); n != 5 {
		t.Errorf("%d connection changes recorded, want created, three updates and deleted", n)
	}
}

// response is a response's status and body.
type response struct {
	code int
	body string
}

// TestDirectoryConnectionLimits checks that a plan without directory sign-in
// can't add a connection.
func TestDirectoryConnectionLimits(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	svc := directoryService(t)
	svc.SetPlanGate(noLDAP{})
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Create(ctx, tx, tenant, CreateInput{Name: "Directory", ServerURL: "ldap://127.0.0.1:1", BindDN: "cn=service,dc=example,dc=test", BindPassword: "x", BaseDN: "dc=example,dc=test"})
	_ = tx.Rollback(ctx)
	if !strings.Contains(errorCode(err), errs.CodeUpgradeRequired) {
		t.Errorf("create on a plan without directory sign-in: %v, want an upgrade", err)
	}
}

// errorCode is err's code, or its text when it has none.
func errorCode(err error) string {
	if e := errs.As(err); e != nil {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}
