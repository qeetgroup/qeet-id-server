package sse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestFrames checks the bytes of each kind of frame and the stream's headers.
func TestFrames(t *testing.T) {
	rec := httptest.NewRecorder()
	s := Open(rec, time.Minute)
	s.Send("token", map[string]string{"text": "hi"})
	s.SendWithID("c1", "activity", map[string]int{"n": 1})
	s.ID("c2")
	s.Retry(3 * time.Second)
	want := "event: token\ndata: {\"text\":\"hi\"}\n\n" +
		"id: c1\nevent: activity\ndata: {\"n\":1}\n\n" +
		"id: c2\n\n" +
		"retry: 3000\n\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("stream:\n%q\nwant\n%q", got, want)
	}
	for k, v := range map[string]string{"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"} {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// TestAnUnmarshalableEventIsSkipped checks that an event whose data can't be
// encoded writes nothing rather than a broken frame.
func TestAnUnmarshalableEventIsSkipped(t *testing.T) {
	rec := httptest.NewRecorder()
	Open(rec, time.Minute).Send("bad", func() {})
	if rec.Body.Len() != 0 {
		t.Errorf("wrote %q", rec.Body.String())
	}
}

// TestKeepAliveStopWaitsForAPing checks that stop returns only once a ping
// being written has finished, so nothing writes after the handler returns.
func TestKeepAliveStopWaitsForAPing(t *testing.T) {
	w := &heldWriter{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}), release: make(chan struct{})}
	stop := Open(w, time.Minute).KeepAlive(time.Millisecond)
	<-w.writing
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("stop returned while a ping was being written")
	case <-time.After(50 * time.Millisecond):
	}
	close(w.release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return once the ping was written")
	}
	if !strings.Contains(w.Body.String(), ": ping\n\n") {
		t.Errorf("wrote %q, want a ping", w.Body.String())
	}
}

// heldWriter holds its first write until release is closed.
type heldWriter struct {
	*httptest.ResponseRecorder
	writing, release chan struct{}
	once             sync.Once
}

func (h *heldWriter) Write(b []byte) (int, error) {
	h.once.Do(func() { close(h.writing); <-h.release })
	return h.ResponseRecorder.Write(b)
}

// noFlush is a ResponseWriter that can't flush.
type noFlush struct{ http.ResponseWriter }

// TestOpenNeedsAFlusher checks that a response that can't flush gets no
// stream and no headers.
func TestOpenNeedsAFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	if s := Open(noFlush{rec}, time.Minute); s != nil {
		t.Fatal("a stream opened on a writer that can't flush")
	}
	if rec.Header().Get("Content-Type") != "" {
		t.Error("headers were set")
	}
}
