package qeetai

import "encoding/json"

// The SSE event names. They must match the frontend StreamEvent union.
const (
	EventTypeThinking   = "thinking"
	EventTypeToken      = "token"
	EventTypeToolCall   = "tool_call"
	EventTypeToolResult = "tool_result"
	EventTypeError      = "error"
	EventTypeDone       = "done"
)

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
