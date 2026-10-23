package qeetai

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// StreamEventType is the SSE event name. Must match the frontend StreamEvent union.
type StreamEventType string

const (
	EventTypeThinking   StreamEventType = "thinking"
	EventTypeToken      StreamEventType = "token"
	EventTypeToolCall   StreamEventType = "tool_call"
	EventTypeToolResult StreamEventType = "tool_result"
	EventTypeError      StreamEventType = "error"
	EventTypeDone       StreamEventType = "done"
)

// sseWriter writes SSE frames to an http.ResponseWriter, flushing after each.
// Writes are serialized because the orchestrator and the keep-alive goroutine
// both write: unsynchronized, a ping could land inside a data line and the two
// would race on net/http's writer state.
type sseWriter struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher

	pingDone chan struct{} // closed by the keep-alive goroutine on exit
}

// newSSEWriter wraps w for SSE use. Returns nil when w does not implement
// http.Flusher (should not happen with a real net/http response).
func newSSEWriter(w http.ResponseWriter) *sseWriter {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return &sseWriter{w: w, flusher: f}
}

// write emits one pre-formatted frame under the lock.
func (s *sseWriter) write(frame string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A failed frame write means the client has gone. There is nothing useful to
	// do about it here — the handler already returns when the request context is
	// cancelled — so the error is discarded explicitly rather than ignored.
	_, _ = fmt.Fprint(s.w, frame)
	s.flusher.Flush()
}

// send writes one SSE frame: "event: <eventType>\ndata: <json>\n\n".
func (s *sseWriter) send(eventType StreamEventType, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		slog.Warn("qeetai: sse marshal", "err", err)
		return
	}
	s.write(fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, raw))
}

// keepAlive writes an SSE comment (": ping") so proxies don't drop an idle
// stream.
func (s *sseWriter) keepAlive() {
	s.write(": ping\n\n")
}

// startKeepAlive launches a goroutine that sends keep-alive pings every d
// until stop is closed. Pair every call with stopKeepAlive.
func (s *sseWriter) startKeepAlive(stop <-chan struct{}, d time.Duration) {
	s.pingDone = make(chan struct{})
	go func() {
		defer close(s.pingDone)
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.keepAlive()
			}
		}
	}()
}

// stopKeepAlive blocks until the keep-alive goroutine has returned, so nothing
// writes to the ResponseWriter after ServeHTTP returns — which net/http
// forbids, and which can otherwise write into a recycled connection.
func (s *sseWriter) stopKeepAlive() {
	if s.pingDone != nil {
		<-s.pingDone
	}
}

// SSE data payload shapes; these must match the frontend StreamEvent union.

type thinkingData struct {
	Text string `json:"text,omitempty"`
}

type tokenData struct {
	Text string `json:"text"`
}

type toolCallData struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type errorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type doneData struct {
	Reason    string `json:"reason"`
	MessageID string `json:"message_id,omitempty"`
}
