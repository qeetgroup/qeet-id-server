// Package ai defines the provider-neutral streaming inference interface used by
// the Qeet AI assistant. Implementations are in the anthropic and openai
// subpackages.
package ai

import (
	"context"
	"encoding/json"
)

// ToolDef is a provider-neutral tool definition. InputSchema is JSON Schema
// in Anthropic's "input_schema" format (identical to OpenAI's "parameters").
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ContentBlock is a provider-neutral content element. Its JSON matches
// Anthropic's content-block format, which is how conversations are stored;
// each provider converts at its boundary.
type ContentBlock struct {
	Type      string          `json:"type"`                  // "text", "tool_use" or "tool_result"
	Text      string          `json:"text,omitempty"`        // text: the text
	ID        string          `json:"id,omitempty"`          // tool_use: the call ID
	Name      string          `json:"name,omitempty"`        // tool_use: the tool name
	Input     json.RawMessage `json:"input,omitempty"`       // tool_use: the JSON input
	ToolUseID string          `json:"tool_use_id,omitempty"` // tool_result: the tool_use ID it answers
	Content   json.RawMessage `json:"content,omitempty"`     // tool_result: the JSON-encoded result
}

// Message is one turn in conversation history. Role is "user", "assistant",
// or "tool" (tool-result turns stored with role="tool" by the DB). Each
// provider remaps roles as needed at the boundary — Anthropic maps "tool" to
// "user"; OpenAI keeps "tool" natively.
type Message struct {
	Role    string
	Content []ContentBlock
}

// EventType classifies a normalized streaming event emitted by a Provider.
type EventType string

const (
	EventTextDelta     EventType = "text_delta"      // a text fragment
	EventToolCallStart EventType = "tool_call_start" // a tool call begins (ToolIndex, ToolID, ToolName)
	EventToolCallDelta EventType = "tool_call_delta" // a fragment of a tool call's JSON input
	EventToolCallStop  EventType = "tool_call_stop"  // a tool call's input is complete; optional
	EventStop          EventType = "stop"            // the turn is done (StopReason)
	EventProviderError EventType = "error"           // a terminal provider error (ErrorMessage)
)

// Event is a normalized streaming event from a Provider. Only the fields for
// its Type are set.
type Event struct {
	Type EventType

	TextDelta      string // EventTextDelta: the text fragment
	ToolIndex      int    // tool-call events: 0-based slot shared by start, delta and stop
	ToolID         string // EventToolCallStart: the provider's call ID (e.g. "toolu_abc123")
	ToolName       string // EventToolCallStart: the manifest tool name (e.g. "search_users")
	ToolInputDelta string // EventToolCallDelta: a fragment of the JSON input
	StopReason     string // EventStop: "end_turn" or "tool_use"
	ErrorMessage   string // EventProviderError: a message with no key material
}

// Provider streams one inference turn. Stream returns an event channel and an
// error channel (capacity 1) that carries any transport error; both close when
// the turn ends, so drain events first. Cancelling ctx aborts the request.
// messages is the full history; system may be empty.
type Provider interface {
	Stream(ctx context.Context, system string, messages []Message, tools []ToolDef) (<-chan Event, <-chan error)
}
