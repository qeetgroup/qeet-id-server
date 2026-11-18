//go:build integration

package authhook

import (
	"errors"
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestHookAtAPrivateAddressIsRefused checks that a hook whose URL is not an
// allowed outbound destination is not created.
func TestHookAtAPrivateAddressIsRefused(t *testing.T) {
	_, err := NewService(dbtest.Pool(t)).Create(dbtest.Context(t), dbtest.Organization(t), "http://127.0.0.1:9/hook", "x", true, audit.Actor{Type: "user"})
	if !errors.Is(err, ErrURLInvalid) {
		t.Errorf("a hook at a private address: %v, want refused", err)
	}
}

// TestAHookShowsHowItAnswersAndCanBeTestedAndMoved checks that a hook counts
// its sign-in calls, skips and denials with its last call and outcome; that a
// test call reports its answer without counting; and that its URL and secret
// can be changed, the new secret signing the next call.
func TestAHookShowsHowItAnswersAndCanBeTestedAndMoved(t *testing.T) {
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
	server.answer(http.StatusOK, `{"decision":"deny","message":"no"}`)
	_, _ = svc.Run(ctx, organization, admin.ID, admin.Email)
	server.answer(http.StatusBadGateway, ``)
	_, _ = svc.Run(ctx, organization, admin.ID, admin.Email)

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/auth-hooks"
	figures := func() Hook {
		t.Helper()
		var list struct {
			Items []Hook `json:"items"`
		}
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base, nil), &list)
		if len(list.Items) != 1 {
			t.Fatalf("hooks %+v", list.Items)
		}
		return list.Items[0]
	}
	got := figures()
	if got.Calls != 3 || got.Denies != 1 || got.Skips != 1 || got.LastCalledAt == nil || got.LastOutcome == nil ||
		*got.LastOutcome != "skipped" || got.LastStatusCode == nil || *got.LastStatusCode != http.StatusBadGateway {
		t.Errorf("figures %+v, want 3 calls, a denial and a skip, the last answered 502", got)
	}

	server.answer(http.StatusOK, `{"decision":"allow","claims":{"plan":"gold"}}`)
	var result TestResult
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, base+"/"+hook.ID.String()+"/test", nil), &result)
	if result.StatusCode != http.StatusOK || result.Decision != "allow" || result.Claims["plan"] != "gold" || server.last["test"] != true {
		t.Errorf("test call %+v (sent %v), want an allow with the hook's claims, marked a test", result, server.last)
	}
	if figures().Calls != 3 {
		t.Error("a test call counted toward the hook's figures")
	}

	moved := newPolicyServer(t, "second-secret")
	if rec := dbtest.Do(t, h, http.MethodPatch, base+"/"+hook.ID.String(), map[string]any{"url": moved.URL, "secret": "second-secret"}); rec.Code != http.StatusOK {
		t.Fatalf("change the URL and secret: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.Run(ctx, organization, admin.ID, admin.Email); err != nil {
		t.Fatal(err)
	}
	if moved.calls != 1 || moved.badSigns != 0 {
		t.Errorf("the moved hook got %d calls, %d badly signed; want one signed with the new secret", moved.calls, moved.badSigns)
	}
}
