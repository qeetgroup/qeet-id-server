// Package sse writes a Server-Sent Events stream (text/event-stream): JSON
// events, reconnect hints, and the keep-alive comments that stop a proxy
// closing an idle stream.
package sse

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Writer writes SSE frames to a response, flushing each. Its lock serializes
// the handler's frames with the keep-alive goroutine's comments, which would
// otherwise land inside a frame and race on net/http's writer state.
type Writer struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
}

// Open starts an event stream on w that may stay open for lifetime: it lifts
// the server's write timeout to that, sets the stream's headers and returns
// its Writer. It returns nil, having written nothing, when w can't flush.
func Open(w http.ResponseWriter, lifetime time.Duration) *Writer {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(lifetime)); err != nil {
		slog.Warn("sse: extend write deadline", "err", err)
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable Nginx/Caddy proxy buffering
	return &Writer{w: w, flusher: f}
}

// write emits one pre-formatted frame under the lock.
func (s *Writer) write(frame string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A failed write means the client has gone; its handler returns when the
	// request context is cancelled, so there is nothing to do here.
	_, _ = fmt.Fprint(s.w, frame) // #nosec G705 -- a text/event-stream of JSON frames and server-made ids, never HTML
	s.flusher.Flush()
}

// Send writes one event: "event: <event>\ndata: <data as JSON>\n\n".
func (s *Writer) Send(event string, data any) {
	s.SendWithID("", event, data)
}

// SendWithID writes one event carrying id, which a reconnecting client sends
// back as Last-Event-ID. An empty id is left out.
func (s *Writer) SendWithID(id, event string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		slog.Warn("sse: marshal", "event", event, "err", err)
		return
	}
	frame := fmt.Sprintf("event: %s\ndata: %s\n\n", event, raw)
	if id != "" {
		frame = "id: " + id + "\n" + frame
	}
	s.write(frame)
}

// ID writes a frame holding only id: the client keeps it as its Last-Event-ID
// without an event to show.
func (s *Writer) ID(id string) {
	s.write("id: " + id + "\n\n")
}

// Retry sets how long the client waits before it reconnects, for a stream
// about to end.
func (s *Writer) Retry(d time.Duration) {
	s.write(fmt.Sprintf("retry: %d\n\n", d.Milliseconds()))
}

// KeepAlive writes a comment every interval until the returned stop is
// called. stop waits for the goroutine to return, so nothing writes to the
// response after the handler returns, which net/http forbids; defer it.
func (s *Writer) KeepAlive(every time.Duration) (stop func()) {
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				s.write(": ping\n\n")
			}
		}
	}()
	return func() {
		close(quit)
		<-done
	}
}
