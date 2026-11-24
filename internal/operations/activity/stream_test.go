package activity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/sse"
)

// TestSendActivityWritesCursorAsID checks that an activity frame starts with an
// id line holding the event's cursor, which a reconnecting client sends back as
// Last-Event-ID.
func TestSendActivityWritesCursorAsID(t *testing.T) {
	rec := httptest.NewRecorder()
	ev := newTestEvent("user.created", SeveritySuccess)
	sendActivity(sse.Open(rec, time.Minute), ev, ev.At)

	frame := rec.Body.String()
	first, _, _ := strings.Cut(frame, "\n")
	cursor, ok := strings.CutPrefix(first, "id: ")
	if !ok {
		t.Fatalf("frame does not start with an id line:\n%s", frame)
	}
	at, id, err := paging.DecodeTimeUUID(cursor)
	if err != nil || !at.Equal(ev.At) || id != ev.ID {
		t.Errorf("frame id decodes to (%s, %s, %v), want (%s, %s)", at, id, err, ev.At, ev.ID)
	}
	if !strings.Contains(frame, "\nevent: activity\ndata: ") || !strings.HasSuffix(frame, "\n\n") {
		t.Errorf("malformed frame:\n%s", frame)
	}
}

// TestStreamEndsWhenTheHubShutsDown checks that an open stream, and one opened
// after, ends with a reconnect hint once the hub shuts down, so a stopping
// server's streams don't hold up its drain.
func TestStreamEndsWhenTheHubShutsDown(t *testing.T) {
	hub := NewHub(nil)
	h := testHandler(t, nil, hub)
	organizationID, userID := uuid.New(), uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &httpx.Principal{OrganizationID: &organizationID, UserID: &userID}
		h.stream(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
	}))
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	read := func() (string, error) {
		resp, err := client.Get(srv.URL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	const want = "retry: 3000\n\n"

	got := make(chan string, 1)
	go func() {
		body, err := read()
		if err != nil {
			body = err.Error()
		}
		got <- body
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		hub.mu.RLock()
		subscribed := len(hub.subs[organizationID]) > 0
		hub.mu.RUnlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stream never subscribed")
		}
	}
	hub.Shutdown()
	if body := <-got; body != want {
		t.Errorf("open stream at shutdown sent %q, want %q", body, want)
	}

	if body, err := read(); err != nil || body != want {
		t.Errorf("stream opened after shutdown sent %q (%v), want %q", body, err, want)
	}
	hub.Shutdown() // a second call is harmless
}

// openStream serves h's stream to reader on a test server and returns a
// channel that gets the whole body once the stream ends, and a func that waits
// until the stream has subscribed to the hub.
func openStream(t *testing.T, h *Handler, reader *httpx.Principal) (<-chan string, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.stream(w, r.WithContext(httpx.WithPrincipal(r.Context(), reader)))
	}))
	t.Cleanup(srv.Close)
	got := make(chan string, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(srv.URL)
		if err != nil {
			got <- err.Error()
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		got <- string(body)
	}()
	subscribed := func() {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			h.Hub.mu.RLock()
			n := len(h.Hub.subs[*reader.OrganizationID])
			h.Hub.mu.RUnlock()
			if n > 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("the stream never subscribed")
			}
		}
	}
	return got, subscribed
}

// ended waits for got, failing if the stream is still open after within.
func ended(t *testing.T, got <-chan string, within time.Duration, what string) string {
	t.Helper()
	select {
	case body := <-got:
		return body
	case <-time.After(within):
		t.Fatalf("%s: the stream is still open after %s", what, within)
		return ""
	}
}

// TestStreamEndsWhenAccessEnds checks that an open stream asks Access again
// and ends, delivering nothing more, once its reader is refused or Access
// can't answer; and that a reader still allowed keeps their stream.
func TestStreamEndsWhenAccessEnds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func() (bool, error)
	}{
		{"access withdrawn", func() (bool, error) { return false, nil }},
		{"access can't be checked", func() (bool, error) { return false, errors.New("store down") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			organizationID, userID := uuid.New(), uuid.New()
			var allowed atomic.Bool
			allowed.Store(true)
			h, err := NewHandler(nil, NewHub(nil), func(context.Context, *httpx.Principal) (bool, error) {
				if allowed.Load() {
					return true, nil
				}
				return tc.answer()
			})
			if err != nil {
				t.Fatal(err)
			}
			h.RecheckEvery = 20 * time.Millisecond
			got, subscribed := openStream(t, h, &httpx.Principal{OrganizationID: &organizationID, UserID: &userID})
			subscribed()
			time.Sleep(100 * time.Millisecond)
			select {
			case <-got:
				t.Fatal("the stream of a reader still allowed ended")
			default:
			}
			allowed.Store(false)
			body := ended(t, got, 2*time.Second, tc.name)
			h.Hub.fanOut(organizationID, newTestEvent("user.created", SeverityInfo))
			if strings.Contains(body, "event: activity") || strings.Contains(body, "retry:") {
				t.Errorf("%s: the stream sent %q, want it to end with nothing more", tc.name, body)
			}
		})
	}
}

// TestStreamEndsWhenTheCredentialExpires checks that a stream ends when the
// credential it was opened with expires, though nothing else ends it.
func TestStreamEndsWhenTheCredentialExpires(t *testing.T) {
	organizationID, userID := uuid.New(), uuid.New()
	expires := time.Now().Add(150 * time.Millisecond)
	got, _ := openStream(t, testHandler(t, nil, NewHub(nil)), &httpx.Principal{OrganizationID: &organizationID, UserID: &userID, ExpiresAt: &expires})
	ended(t, got, 2*time.Second, "an expired credential")
	if time.Now().Before(expires) {
		t.Error("the stream ended before its credential expired")
	}
}

// TestStreamReconnectsWhenItFallsBehind checks that a stream whose hub buffer
// overflowed ends with a reconnect hint, so the client catches up from the
// audit log instead of silently missing events.
func TestStreamReconnectsWhenItFallsBehind(t *testing.T) {
	organizationID, userID := uuid.New(), uuid.New()
	h := testHandler(t, nil, NewHub(nil))
	got, subscribed := openStream(t, h, &httpx.Principal{OrganizationID: &organizationID, UserID: &userID})
	subscribed()
	h.Hub.mu.RLock()
	sub := h.Hub.subs[organizationID][0]
	h.Hub.mu.RUnlock()
	// The hub tells a subscriber it lost an event as fanOut does on a full
	// channel (TestHubSlowConsumerIsToldItLostAnEvent).
	sub.lostOnce.Do(func() { close(sub.lost) })
	if body := ended(t, got, 2*time.Second, "a lagging stream"); !strings.HasSuffix(body, "retry: 3000\n\n") {
		t.Errorf("a lagging stream ended with %q, want a reconnect hint", body[max(0, len(body)-80):])
	}
}
