//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// A sign-in's approval request is handed to the push service as a
// high-priority message that lives as long as the request can be answered,
// with the access token when one is set; the service's answer is read, so a
// request that reaches no phone is refused and closed at once, and a phone the
// app is gone from is no longer sent to.

type sentPush struct {
	To        string         `json:"to"`
	Data      map[string]any `json:"data"`
	Priority  string         `json:"priority"`
	TTL       int            `json:"ttl"`
	ChannelID string         `json:"channelId"`
}

// fakePushService stands in for Expo's push API: it records each message and
// answers with the ticket set for its token ("ok" unless told otherwise), or
// with status when it is set.
type fakePushService struct {
	mu      sync.Mutex
	sent    []sentPush
	auth    []string
	tickets map[string]string // token → details.error
	status  int
}

func newFakePushService(t *testing.T) (*fakePushService, *httptest.Server) {
	t.Helper()
	f := &fakePushService{tickets: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msgs []sentPush
		_ = json.Unmarshal(raw, &msgs)
		f.mu.Lock()
		f.sent = append(f.sent, msgs...)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		status := f.status
		tickets := make(map[string]string, len(f.tickets))
		for k, v := range f.tickets {
			tickets[k] = v
		}
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errors":[{"code":"INTERNAL_SERVER_ERROR","message":"down"}]}`))
			return
		}
		out := make([]map[string]any, 0, len(msgs))
		for _, m := range msgs {
			if reason := tickets[m.To]; reason != "" {
				out = append(out, map[string]any{"status": "error", "message": m.To + " is not registered",
					"details": map[string]any{"error": reason}})
				continue
			}
			out = append(out, map[string]any{"status": "ok", "id": uuid.NewString()})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

// answer sets how the service answers from now on: status (0 = 200 with
// tickets) and the refusal for one token.
func (f *fakePushService) answer(status int, token, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
	if token != "" {
		f.tickets[token] = reason
	}
}

func (f *fakePushService) messages() []sentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentPush(nil), f.sent...)
}

func pushMFA(t *testing.T, url string) *mfa.Service {
	t.Helper()
	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, url)
	svc.SetCipher(testEnvelope(t))
	return svc
}

func expoToken() string { return "ExponentPushToken[" + uniqueSlug("tok") + "]" }

func pushRequests(t *testing.T, ctx context.Context, userID uuid.UUID, status string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_push_challenges WHERE user_id = $1 AND status = $2`,
		userID, status).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestApprovalRequestReachesThePushService: the message names the request,
// is high priority, lives two minutes, uses the app's approval channel and
// carries the access token.
func TestApprovalRequestReachesThePushService(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	fake, srv := newFakePushService(t)
	svc := pushMFA(t, srv.URL)
	svc.SetExpoAccessToken("expo-access")
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("push-send")))
	tok := expoToken()
	if _, _, err := svc.RegisterPushDevice(ctx, userID, "Phone", tok, "android"); err != nil {
		t.Fatal(err)
	}

	id, expires, err := svc.StartLoginPush(ctx, userID, "198.51.100.7", "Chrome on macOS")
	if err != nil {
		t.Fatalf("a delivered request must start: %v", err)
	}
	if time.Until(expires) < 100*time.Second || time.Until(expires) > 2*time.Minute {
		t.Fatalf("the request lives two minutes, expires %v", expires)
	}
	sent := fake.messages()
	if len(sent) != 1 {
		t.Fatalf("one phone, one message: %+v", sent)
	}
	m := sent[0]
	if m.To != tok || m.Data["challenge_id"] != id.String() || m.Priority != "high" || m.TTL != 120 || m.ChannelID != "push-mfa" {
		t.Fatalf("the message must name the request and be delivered at once, for two minutes: %+v", m)
	}
	fake.mu.Lock()
	auth := fake.auth[0]
	fake.mu.Unlock()
	if auth != "Bearer expo-access" {
		t.Fatalf("the access token must be sent: %q", auth)
	}
}

// TestUndeliveredApprovalRequestIsClosed: when the push service fails or
// refuses every message, starting push approval is refused with
// mfa.push_delivery_failed and the request is closed, not left pending.
func TestUndeliveredApprovalRequestIsClosed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	fake, srv := newFakePushService(t)
	svc := pushMFA(t, srv.URL)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("push-fail")))
	tok := expoToken()
	if _, _, err := svc.RegisterPushDevice(ctx, userID, "Phone", tok, "ios"); err != nil {
		t.Fatal(err)
	}

	fake.answer(http.StatusInternalServerError, "", "")
	if _, _, err := svc.StartLoginPush(ctx, userID, "", ""); errs.As(err) == nil || errs.As(err).Code != errs.CodeMFAPushDeliveryFailed {
		t.Fatalf("a request the push service could not take must be refused: %v", err)
	}
	fake.answer(0, tok, "MessageRateExceeded")
	if _, _, err := svc.StartLoginPush(ctx, userID, "", ""); errs.As(err) == nil || errs.As(err).Code != errs.CodeMFAPushDeliveryFailed {
		t.Fatalf("a message the push service refused must be refused: %v", err)
	}
	if pending, closed := pushRequests(t, ctx, userID, "pending"), pushRequests(t, ctx, userID, "expired"); pending != 0 || closed != 2 {
		t.Fatalf("undelivered requests must be closed: %d pending, %d expired", pending, closed)
	}
}

// TestPhoneWithoutTheAppIsRetired: a phone the push service reports as no
// longer registered is retired — not sent to again, not offered — while the
// person's other phone still gets the request.
func TestPhoneWithoutTheAppIsRetired(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	fake, srv := newFakePushService(t)
	svc := pushMFA(t, srv.URL)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("push-gone")))
	gone, kept := expoToken(), expoToken()
	for _, tok := range []string{gone, kept} {
		if _, _, err := svc.RegisterPushDevice(ctx, userID, "Phone", tok, "ios"); err != nil {
			t.Fatal(err)
		}
	}
	fake.answer(0, gone, "DeviceNotRegistered")
	if _, _, err := svc.StartLoginPush(ctx, userID, "", ""); err != nil {
		t.Fatalf("the other phone got it, so the request starts: %v", err)
	}
	var live int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM auth.mfa_push_devices WHERE user_id = $1 AND device_token_expires_at > NOW()`, userID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("the phone without the app must be retired, %d live", live)
	}
	before := len(fake.messages())
	if _, _, err := svc.StartLoginPush(ctx, userID, "", ""); err != nil {
		t.Fatal(err)
	}
	after := fake.messages()[before:]
	if len(after) != 1 || after[0].To != kept {
		t.Fatalf("only the phone with the app is sent the next request: %+v", after)
	}
}
