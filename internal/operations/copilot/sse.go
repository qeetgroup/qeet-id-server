package copilot

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

// sseWriter writes SSE frames to an http.ResponseWriter and flushes after
// each frame. The response must have Content-Type: text/event-stream set
// before the first write.
type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
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

// send writes one SSE frame: "event: <eventType>\ndata: <json>\n\n".
func (s *sseWriter) send(eventType StreamEventType, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		slog.Warn("copilot: sse marshal", "err", err)
		return
	}
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", eventType, raw)
	s.flusher.Flush()
}

// keepAlive sends a comment ping (":\n\n") to prevent proxy timeouts.
// Call it periodically from a ticker goroutine.
func (s *sseWriter) keepAlive() {
	fmt.Fprintf(s.w, ": ping\n\n")
	s.flusher.Flush()
}

// startKeepAlive launches a goroutine that sends keep-alive pings every d
// until done is closed.
func (s *sseWriter) startKeepAlive(done <-chan struct{}, d time.Duration) {
	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.keepAlive()
			}
		}
	}()
}

// SSE data payload shapes — must match the frontend StreamEvent union in §A.4.

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

type toolResultData struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

type errorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type doneData struct {
	Reason    string `json:"reason"`
	MessageID string `json:"message_id,omitempty"`
}
