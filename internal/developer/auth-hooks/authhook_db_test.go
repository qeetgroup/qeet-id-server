//go:build integration

package authhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// policyServer is a fake sign-in hook: it checks each call's signature against
// secret and answers with status and reply.
type policyServer struct {
	*httptest.Server
	mu       sync.Mutex
	secret   string
	status   int
	reply    string
	calls    int
	badSigns int
	last     map[string]any
}

// newPolicyServer starts a hook that allows every sign-in until t ends.
func newPolicyServer(t *testing.T, secret string) *policyServer {
	p := &policyServer{secret: secret, status: http.StatusOK, reply: `{"decision":"allow"}`}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.calls++
		if r.Header.Get("X-Qeet-Signature") != "sha256="+sign(p.secret, body) {
			p.badSigns++
		}
		p.last = nil
		_ = json.Unmarshal(body, &p.last)
		w.WriteHeader(p.status)
		_, _ = io.WriteString(w, p.reply)
	}))
	t.Cleanup(p.Close)
	return p
}

// answer makes the hook answer the next calls with status and reply.
func (p *policyServer) answer(status int, reply string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status, p.reply = status, reply
}

// hookService returns the hook service, allowed to call loopback hooks.
func hookService(t *testing.T) *Service {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(dbtest.Pool(t), egress.DevelopmentPolicy())
	svc.SetCipher(box)
	return svc
}

// skips counts the organisation's auth_hook.skipped audit events.
func skips(t *testing.T, tenantID uuid.UUID) int {
	t.Helper()
	var n int
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'auth_hook.skipped'
	`, tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHookDecidesSignIn checks that an organisation's hook, managed over HTTP,
// is called signed with the person's details and allows, adds claims or
// refuses; that when it gives no answer fail_open decides and the skip is
// recorded; and that a disabled hook, or another organisation's, isn't called.
func TestHookDecidesSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := hookService(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	policy := newPolicyServer(t, "s3cret-signing-key")
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	base := "/tenants/" + tenant.String() + "/auth-hooks"

	rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"url": policy.URL, "secret": "s3cret-signing-key"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var hook Hook
	dbtest.Decode(t, rec, &hook)
	if !hook.Enabled || !hook.FailOpen || hook.Trigger != "post_login" {
		t.Errorf("new hook %+v; want enabled, failing open, after sign-in", hook)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"url": "ftp://hooks.example.com"}); rec.Code/100 != 4 {
		t.Errorf("a hook at a non-http URL: %d, want refused", rec.Code)
	}

	if claims, err := svc.Run(ctx, tenant, admin.ID, admin.Email); err != nil || claims != nil {
		t.Errorf("allowed: %v, %v", claims, err)
	}
	if policy.badSigns != 0 || policy.last["email"] != admin.Email || policy.last["user_id"] != admin.ID.String() {
		t.Errorf("the hook got %v with %d bad signatures; want the person's details, signed", policy.last, policy.badSigns)
	}
	policy.answer(http.StatusOK, `{"decision":"allow","claims":{"department":"finance"}}`)
	if claims, err := svc.Run(ctx, tenant, admin.ID, admin.Email); err != nil || claims["department"] != "finance" {
		t.Errorf("allowed with claims: %v, %v", claims, err)
	}
	policy.answer(http.StatusOK, `{"decision":"deny","message":"Outside office hours."}`)
	var denied *errs.Error
	if _, err := svc.Run(ctx, tenant, admin.ID, admin.Email); !errors.As(err, &denied) || denied.Code != errs.CodeAuthHookDenied || denied.Message != "Outside office hours." {
		t.Errorf("denied: %v; want the hook's message", err)
	}

	policy.answer(http.StatusBadGateway, "")
	if _, err := svc.Run(ctx, tenant, admin.ID, admin.Email); err != nil {
		t.Errorf("a failing hook that fails open refused the sign-in: %v", err)
	}
	if n := skips(t, tenant); n != 1 {
		t.Errorf("%d skips recorded, want 1", n)
	}
	if rec := dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]bool{"enabled": true, "fail_open": false}); rec.Code != http.StatusOK {
		t.Fatalf("make the hook fail closed: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Run(ctx, tenant, admin.ID, admin.Email); !errors.Is(err, errs.ErrAuthHookDenied) {
		t.Errorf("a failing hook that fails closed: %v, want refused", err)
	}
	policy.answer(http.StatusOK, "not json")
	if _, err := svc.Run(ctx, tenant, admin.ID, admin.Email); !errors.Is(err, errs.ErrAuthHookDenied) {
		t.Errorf("an unreadable answer from a hook that fails closed: %v, want refused", err)
	}
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.Run(gone, tenant, admin.ID, admin.Email); !errors.Is(err, errs.ErrAuthHookDenied) {
		t.Errorf("a hook that can't be read, last seen failing closed: %v, want refused", err)
	}
	if _, err := svc.Run(gone, other, admin.ID, admin.Email); err != nil {
		t.Errorf("a hook that can't be read and was never seen: %v, want allowed", err)
	}

	calls := policy.calls
	if _, err := svc.Run(ctx, other, admin.ID, admin.Email); err != nil || policy.calls != calls {
		t.Errorf("an organisation without a hook: %v, %d calls", err, policy.calls-calls)
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	otherBase := "/tenants/" + other.String() + "/auth-hooks/" + hook.ID.String()
	if rec := dbtest.Do(t, asOther, http.MethodPatch, otherBase, map[string]bool{"enabled": false}); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation changing the hook: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asOther, http.MethodDelete, otherBase, nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation deleting the hook: %d, want 404", rec.Code)
	}

	if rec := dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	calls = policy.calls
	if _, err := svc.Run(ctx, tenant, admin.ID, admin.Email); err != nil || policy.calls != calls {
		t.Errorf("a disabled hook: %v, %d calls", err, policy.calls-calls)
	}
	var list struct {
		Items []Hook `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 1 || list.Items[0].Enabled {
		t.Errorf("hooks %+v; want the one, disabled", list.Items)
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+hook.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
}

// TestHookSecretIsEncryptedOnUse checks that a hook stored with a plaintext
// secret signs with it, and has it encrypted the first time it runs.
func TestHookSecretIsEncryptedOnUse(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := hookService(t)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	policy := newPolicyServer(t, "older-plain-secret")
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.auth_hooks (tenant_id, url, secret) VALUES ($1, $2, 'older-plain-secret')`, tenant, policy.URL); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := svc.Run(ctx, tenant, a.ID, a.Email); err != nil {
			t.Fatal(err)
		}
	}
	var plain string
	var version int
	if err := pool.QueryRow(ctx, `SELECT secret, encryption_version FROM tenant.auth_hooks WHERE tenant_id = $1`, tenant).Scan(&plain, &version); err != nil {
		t.Fatal(err)
	}
	if plain != "" || version != 1 {
		t.Errorf("after use the secret is %q at version %d; want it encrypted", plain, version)
	}
	if policy.calls != 2 || policy.badSigns != 0 {
		t.Errorf("%d calls, %d with a bad signature; want both signed with the stored secret", policy.calls, policy.badSigns)
	}

	_, err := NewService(pool).Create(ctx, tenant, "http://127.0.0.1:9/hook", "x", true, audit.Actor{Type: "user"})
	if !errors.Is(err, errs.ErrAuthHookURLInvalid) {
		t.Errorf("a hook at a private address: %v, want refused", err)
	}
}
