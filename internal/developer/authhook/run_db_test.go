//go:build integration

package authhook

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestHookDecidesSignIn checks that an organization's hook, managed over HTTP,
// is called signed with the person's details and allows, adds claims or
// refuses; that when it gives no answer fail_open decides and the skip is
// recorded; and that a disabled hook, or another organization's, isn't called.
func TestHookDecidesSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := hookService(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	policy := newPolicyServer(t, "s3cret-signing-key")
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/auth-hooks"

	rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"url": policy.URL, "secret": "s3cret-signing-key"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var hook Hook
	dbtest.Decode(t, rec, &hook)
	if !hook.Enabled || !hook.FailOpen || hook.Trigger != "post_login" {
		t.Errorf("new hook %+v; want enabled, failing open, after sign-in", hook)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.auth_hooks WHERE id = $1 AND organization_id = $2 AND created_by = $3`, hook.ID, organization, admin.ID); n != 1 {
		t.Error("the hook doesn't record who created it")
	}
	if rec := dbtest.Do(t, h, http.MethodPost, base, map[string]string{"url": "ftp://hooks.example.com"}); rec.Code/100 != 4 {
		t.Errorf("a hook at a non-http URL: %d, want refused", rec.Code)
	}

	if claims, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil || claims != nil {
		t.Errorf("allowed: %v, %v", claims, err)
	}
	if policy.badSigns != 0 || policy.last["email"] != admin.Email || policy.last["user_id"] != admin.ID.String() {
		t.Errorf("the hook got %v with %d bad signatures; want the person's details, signed", policy.last, policy.badSigns)
	}
	policy.answer(http.StatusOK, `{"decision":"allow","claims":{"department":"finance"}}`)
	if claims, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil || claims["department"] != "finance" {
		t.Errorf("allowed with claims: %v, %v", claims, err)
	}
	policy.answer(http.StatusOK, `{"decision":"deny","message":"Outside office hours."}`)
	var denied *errs.Error
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); !errors.As(err, &denied) || denied.Code != errs.CodeAuthHookDenied || denied.Message != "Outside office hours." {
		t.Errorf("denied: %v; want the hook's message", err)
	}

	policy.answer(http.StatusBadGateway, "")
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil {
		t.Errorf("a failing hook that fails open refused the sign-in: %v", err)
	}
	if n := skips(t, organization); n != 1 {
		t.Errorf("%d skips recorded, want 1", n)
	}
	if rec := dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]bool{"enabled": true, "fail_open": false}); rec.Code != http.StatusOK {
		t.Fatalf("make the hook fail closed: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); !errors.Is(err, errs.ErrAuthHookDenied) {
		t.Errorf("a failing hook that fails closed: %v, want refused", err)
	}
	policy.answer(http.StatusOK, "not json")
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); !errors.Is(err, errs.ErrAuthHookDenied) {
		t.Errorf("an unreadable answer from a hook that fails closed: %v, want refused", err)
	}
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.Run(gone, organization, admin.ID, admin.Email); !errors.Is(err, errs.ErrAuthHookDenied) {
		t.Errorf("a hook that can't be read, last seen failing closed: %v, want refused", err)
	}
	if _, err := svc.Run(gone, other, admin.ID, admin.Email); err != nil {
		t.Errorf("a hook that can't be read and was never seen: %v, want allowed", err)
	}

	calls := policy.calls
	if _, err := svc.Run(ctx, other, admin.ID, admin.Email); err != nil || policy.calls != calls {
		t.Errorf("an organization without a hook: %v, %d calls", err, policy.calls-calls)
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), (&Handler{Service: svc}).Mount)
	otherBase := "/organizations/" + other.String() + "/auth-hooks/" + hook.ID.String()
	if rec := dbtest.Do(t, asOther, http.MethodPatch, otherBase, map[string]bool{"enabled": false}); rec.Code != http.StatusNotFound {
		t.Errorf("another organization changing the hook: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asOther, http.MethodDelete, otherBase, nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization deleting the hook: %d, want 404", rec.Code)
	}

	if rec := dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	calls = policy.calls
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil || policy.calls != calls {
		t.Errorf("a disabled hook: %v, %d calls", err, policy.calls-calls)
	}
	var list struct {
		Items []Hook `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 1 || list.Items[0].Enabled {
		t.Errorf("hooks %+v; want the one, disabled", list.Items)
	}

	// A PATCH changes only the fields it sends.
	var got struct {
		Enabled  bool `json:"enabled"`
		FailOpen bool `json:"fail_open"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]bool{"fail_open": true}), &got)
	if got.Enabled || !got.FailOpen {
		t.Errorf("after sending only fail_open: %+v, want still disabled and failing open", got)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]bool{"enabled": true}), &got)
	if !got.Enabled || !got.FailOpen {
		t.Errorf("after sending only enabled: %+v, want enabled and still failing open", got)
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+hook.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
}

// TestEveryEnabledHookRuns checks that each of an organization's enabled hooks
// is called, oldest first, with all their claims added and a later hook's
// winning a clash; that the first to deny ends the sign-in before the rest are
// called; and that each hook's own fail_open decides when it gives no answer.
func TestEveryEnabledHookRuns(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := hookService(t)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	first, second := newPolicyServer(t, "first-secret"), newPolicyServer(t, "second-secret")
	older, err := svc.Create(ctx, organization, first.URL, "first-secret", true, audit.Actor{Type: "user"})
	if err != nil {
		t.Fatal(err)
	}
	newer, err := svc.Create(ctx, organization, second.URL, "second-secret", true, audit.Actor{Type: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE organization.auth_hooks SET created_at = NOW() - INTERVAL '1 hour' WHERE id = $1 AND organization_id = $2`, older.ID, organization); err != nil {
		t.Fatal(err)
	}
	calls := func() (int, int) {
		first.mu.Lock()
		defer first.mu.Unlock()
		second.mu.Lock()
		defer second.mu.Unlock()
		return first.calls, second.calls
	}

	first.answer(http.StatusOK, `{"decision":"allow","claims":{"department":"finance","source":"first"}}`)
	second.answer(http.StatusOK, `{"decision":"allow","claims":{"region":"in","source":"second"}}`)
	claims, err := svc.Run(ctx, organization, a.ID, a.Email)
	if err != nil || claims["department"] != "finance" || claims["region"] != "in" || claims["source"] != "second" {
		t.Errorf("both allow: %v, %v; want both hooks' claims, the newer winning a clash", claims, err)
	}
	first.mu.Lock()
	second.mu.Lock()
	f, s, bad := first.calls, second.calls, first.badSigns+second.badSigns
	second.mu.Unlock()
	first.mu.Unlock()
	if f != 1 || s != 1 || bad != 0 {
		t.Errorf("calls %d and %d, %d badly signed; want each hook called once, signed with its own secret", f, s, bad)
	}

	first.answer(http.StatusOK, `{"decision":"deny","message":"Blocked by the first hook."}`)
	var denied *errs.Error
	if _, err := svc.Run(ctx, organization, a.ID, a.Email); !errors.As(err, &denied) || denied.Message != "Blocked by the first hook." {
		t.Errorf("the older hook denies: %v; want its refusal", err)
	}
	if _, s := calls(); s != 1 {
		t.Errorf("the newer hook was called after the older one denied")
	}

	first.answer(http.StatusBadGateway, "")
	if claims, err := svc.Run(ctx, organization, a.ID, a.Email); err != nil || claims["region"] != "in" {
		t.Errorf("the older hook fails open: %v, %v; want the newer one to decide", claims, err)
	}
	if _, s := calls(); s != 2 || skips(t, organization) != 1 {
		t.Errorf("the newer hook called %d times, %d skips; want it called and the skip recorded", s, skips(t, organization))
	}

	first.answer(http.StatusOK, `{"decision":"allow"}`)
	second.answer(http.StatusBadGateway, "")
	on, closed := true, false
	if _, _, err := svc.Update(ctx, newer.ID, organization, HookSettings{Enabled: &on, FailOpen: &closed}, audit.Actor{Type: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Run(ctx, organization, a.ID, a.Email); !errors.Is(err, errs.ErrAuthHookDenied) {
		t.Errorf("the newer hook fails closed: %v, want refused", err)
	}

	off := false
	if _, _, err := svc.Update(ctx, newer.ID, organization, HookSettings{Enabled: &off}, audit.Actor{Type: "user"}); err != nil {
		t.Fatal(err)
	}
	f, s = calls()
	if _, err := svc.Run(ctx, organization, a.ID, a.Email); err != nil {
		t.Errorf("only the older hook enabled: %v", err)
	}
	if f2, s2 := calls(); f2 != f+1 || s2 != s {
		t.Errorf("a disabled hook was called, or an enabled one wasn't: %d and %d more calls", f2-f, s2-s)
	}
}

// TestHookRequestsCarryASignedTimestamp checks that a hook call is signed as a
// webhook delivery is, over a timestamp and the body, so a receiver refuses a
// replayed one; that a hook given a new secret signs with the old one too for
// a day, so its endpoint can move over, and that the hook shows until when;
// and that once the overlap has ended only the new one signs.
func TestHookRequestsCarryASignedTimestamp(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := hookService(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	server := newPolicyServer(t, "first-secret")
	hook, err := svc.Create(ctx, organization, server.URL, "first-secret", true, audit.Actor{Type: "user", UserID: &admin.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil {
		t.Fatal(err)
	}
	if server.calls != 1 || server.badSigns != 0 {
		t.Fatalf("%d calls, %d not signed over a fresh timestamp and the body", server.calls, server.badSigns)
	}

	server.secret, server.old = "second-secret", "first-secret"
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/auth-hooks"
	if rec := dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]any{"secret": "second-secret"}); rec.Code != http.StatusOK {
		t.Fatalf("change the secret: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil {
		t.Fatal(err)
	}
	if server.calls != 2 || server.badSigns != 0 || server.oldSigns != 1 {
		t.Errorf("after the change: %d calls, %d not signed with the new secret, %d with the old; want one signed with both",
			server.calls, server.badSigns, server.oldSigns)
	}
	var list struct {
		Items []Hook `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 1 || list.Items[0].PreviousSecretExpiresAt == nil || time.Until(*list.Items[0].PreviousSecretExpiresAt) < 23*time.Hour {
		t.Errorf("hooks %+v, want the old secret signing for a day", list.Items)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.auth_hooks SET previous_secret_expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, hook.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil {
		t.Fatal(err)
	}
	if server.calls != 3 || server.badSigns != 0 || server.oldSigns != 1 {
		t.Errorf("after the overlap: %d calls, %d not signed with the new secret, %d with the old; want the last signed with the new one only",
			server.calls, server.badSigns, server.oldSigns)
	}
}
