// Package ai defines the provider-neutral inference abstraction for the AI
// copilot. Implementations live in platform/ai/{anthropic,openai}; the copilot
// orchestrator depends only on Provider. Arch rule: platform/* must not import
// domains/*.
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

// ContentBlock is a provider-neutral content element whose JSON shape matches
// the Anthropic content-block format — the canonical storage format used in
// the copilot DB. Each provider converts to/from its own wire format at the
// boundary; the orchestrator and DB always use this neutral form.
//
// Fields:
//
//	Type      — "text" | "tool_use" | "tool_result"
//	Text      — text blocks
//	ID        — tool_use: the tool call id
//	Name      — tool_use / tool_result: the tool name
//	Input     — tool_use: JSON input object
//	ToolUseID — tool_result: links back to the tool_use.id
//	Content   — tool_result: JSON-encoded result string or object
type ContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
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
	// EventTextDelta carries a text fragment streamed from the model.
	EventTextDelta EventType = "text_delta"

	// EventToolCallStart signals the beginning of a tool-call block. ToolIndex
	// identifies which accumulator slot to use (0-based, per-turn counter).
	EventToolCallStart EventType = "tool_call_start"

	// EventToolCallDelta carries one streaming fragment of the tool-call's
	// JSON input. ToolIndex identifies the target accumulator.
	EventToolCallDelta EventType = "tool_call_delta"

	// EventToolCallStop signals that a tool-call's input is complete. Providers
	// may omit this; the orchestrator treats it as a no-op.
	EventToolCallStop EventType = "tool_call_stop"

	// EventStop signals the model has finished generating for this turn.
	// StopReason is "end_turn" (text reply) or "tool_use" (tool calls issued).
	EventStop EventType = "stop"

	// EventProviderError signals a terminal error from the provider. The
	// orchestrator emits an error SSE frame and closes the stream.
	EventProviderError EventType = "error"
)

// Event is a normalized streaming event emitted by any Provider. Only the
// fields relevant to the Event.Type are set; all others are zero.
type Event struct {
	Type EventType

	// EventTextDelta: text fragment.
	TextDelta string

	// EventToolCallStart: tool call identity.
	ToolIndex int    // 0-based slot; matches subsequent delta/stop events
	ToolID    string // provider-assigned call id (e.g. "toolu_abc123")
	ToolName  string // tool manifest name (e.g. "search_users")

	// EventToolCallDelta: streaming fragment of the tool JSON input.
	// ToolIndex from EventToolCallStart identifies the target accumulator.
	ToolInputDelta string

	// EventStop: why the model stopped.
	StopReason string // "end_turn" | "tool_use"

	// EventProviderError: human-readable message (no key material).
	ErrorMessage string
}

// Provider is the inference backend abstraction consumed by the copilot
// orchestrator. Implementations are in platform/ai/anthropic and
// platform/ai/openai; the orchestrator depends only on this interface.
//
// Stream initiates one streaming inference turn and returns:
//   - events: channel of normalized Event values, closed on stream end.
//   - errC:   buffered channel (cap 1) carrying the final transport error
//     if any; closed after events.
//
// Callers must drain events before reading errC. Cancelling ctx aborts the
// in-flight request and closes both channels.
//
// Parameters:
//   - system   — system prompt (may be empty).
//   - messages — full conversation history in neutral DB format (Anthropic
//     content-block JSON); each provider converts at the boundary.
//   - tools    — available tool definitions from the manifest.
type Provider interface {
	Stream(ctx context.Context, system string, messages []Message, tools []ToolDef) (<-chan Event, <-chan error)
}
