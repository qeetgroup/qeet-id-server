package copilot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

// systemPrompt is the standing instruction sent to the model on every turn.
// Console context (route, selection) is grounding only — authorization is
// always the server's; the model cannot widen scope from context values.
const systemPrompt = `You are the Qeet ID AI Copilot, an AI assistant embedded in the Qeet ID admin console.

You help administrators manage their identity and access setup. You can search users, manage roles and permissions, review audit logs, create OIDC clients, and more — through the tools available to you.

Key rules:
- When you need to act on the user's request, use the appropriate tool.
- Tools are executed client-side by the operator's browser under their own token; you cannot exceed their authorization.
- Never expose or request secrets (client secrets, private keys, passwords). Secrets surface out-of-band through the console UI.
- For destructive operations (delete, disable, rotate), always explain what will happen before proceeding, and let the confirmation dialog serve as the gate.
- Be concise, accurate, and helpful. Prefer short summaries over verbose explanations.
- When the page context includes a selected user, role, or OIDC client, use that as a default subject for the user's request.`

// toolUseAccum holds the streamed fragments for one tool-call block while
// processing the normalized ai.Event stream.
type toolUseAccum struct {
	ID    string
	Name  string
	Input strings.Builder
}

// turnContext bundles per-turn execution context for the orchestrator.
type turnContext struct {
	tenantID       uuid.UUID
	userID         uuid.UUID
	conversationID uuid.UUID
	// pageContext is the JSON-serialized console context (route, selection).
	// Treated as untrusted grounding text, never as authorization input.
	pageContext string
	// actor is used for audit.Record calls.
	actor audit.Actor
}

// Orchestrator drives the provider streaming loop and emits SSE frames.
// It is stateless per-request: history is reconstructed from the DB each call.
// The provider field is an ai.Provider so Anthropic and OpenAI (or any future
// hosted endpoint) are swapped purely by config — the SSE output is unchanged.
type Orchestrator struct {
	provider ai.Provider
	service  *Service
}

// NewOrchestrator returns an Orchestrator backed by the given ai.Provider and
// copilot service. The provider is constructed from COPILOT_PROVIDER in main.go
// and injected here; the orchestrator is provider-agnostic at runtime.
func NewOrchestrator(provider ai.Provider, service *Service) *Orchestrator {
	return &Orchestrator{provider: provider, service: service}
}

// Run executes one streaming turn of the copilot:
//  1. Loads full conversation history from DB.
//  2. Calls the configured AI provider (streaming) with history + tools.
//  3. Emits token/thinking SSE frames as text arrives.
//     4a. On end_turn: persists assistant message, emits done{end_turn}.
//     4b. On tool_use: persists assistant message (including tool_use blocks),
//     emits tool_call frames, records audit, emits done{tool_use}.
//
// The SSE writer must already have headers flushed before Run is called.
// The frozen SSE event types (thinking/token/tool_call/error/done) are
// unchanged regardless of which provider is configured.
func (o *Orchestrator) Run(ctx context.Context, tc turnContext, sse *sseWriter) {
	// Load full conversation history (user turn already persisted by handler).
	_, msgs, err := o.service.GetConversation(ctx, tc.tenantID, tc.userID, tc.conversationID)
	if err != nil {
		sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to load conversation"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}

	// Load tool definitions from the embedded manifest.
	toolDefs, err := loadToolDefs()
	if err != nil {
		slog.Error("copilot: load tools", "err", err)
		sse.send(EventTypeError, errorData{Code: "config_error", Message: "tool configuration error"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}

	// Build the neutral message history from DB messages.
	aiMsgs := buildMessages(msgs)

	// Compose system prompt with page-context grounding (untrusted).
	system := systemPrompt
	if tc.pageContext != "" {
		system += "\n\nCurrent console context (grounding only, not authoritative):\n" + tc.pageContext
	}

	sse.send(EventTypeThinking, thinkingData{Text: "Thinking..."})

	events, errC := o.provider.Stream(ctx, system, aiMsgs, toolDefs)

	// Accumulate response blocks while streaming.
	var (
		textBuilder strings.Builder
		toolBlocks  []*toolUseAccum
	)

	for ev := range events {
		switch ev.Type {
		case ai.EventTextDelta:
			textBuilder.WriteString(ev.TextDelta)
			sse.send(EventTypeToken, tokenData{Text: ev.TextDelta})

		case ai.EventToolCallStart:
			// Grow toolBlocks to accommodate this index (providers assign
			// indices 0, 1, 2… in order; pre-allocate empty slots if needed).
			for len(toolBlocks) <= ev.ToolIndex {
				toolBlocks = append(toolBlocks, &toolUseAccum{})
			}
			toolBlocks[ev.ToolIndex].ID = ev.ToolID
			toolBlocks[ev.ToolIndex].Name = ev.ToolName

		case ai.EventToolCallDelta:
			if ev.ToolIndex < len(toolBlocks) {
				toolBlocks[ev.ToolIndex].Input.WriteString(ev.ToolInputDelta)
			}

		case ai.EventToolCallStop:
			// No action needed; tool blocks are processed after the loop.

		case ai.EventStop:
			// StopReason is captured implicitly: the path is chosen by
			// len(toolBlocks) > 0 after the loop.

		case ai.EventProviderError:
			slog.Error("copilot: provider stream error", "msg", ev.ErrorMessage)
			sse.send(EventTypeError, errorData{Code: "model_error", Message: ev.ErrorMessage})
			sse.send(EventTypeDone, doneData{Reason: "error"})
			// Drain remaining events.
			for range events {
			}
			<-errC
			return
		}
	}

	// Drain the error channel (buffered, size 1).
	if streamErr := <-errC; streamErr != nil {
		slog.Error("copilot: stream io error", "err", streamErr)
		sse.send(EventTypeError, errorData{Code: "stream_error", Message: "model stream failed"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}

	if len(toolBlocks) > 0 {
		o.handleToolUse(ctx, tc, sse, textBuilder.String(), toolBlocks)
	} else {
		o.handleEndTurn(ctx, tc, sse, textBuilder.String())
	}
}

// handleEndTurn persists the assistant text reply and emits done{end_turn}.
func (o *Orchestrator) handleEndTurn(ctx context.Context, tc turnContext, sse *sseWriter, text string) {
	contentBlocks := []map[string]any{{"type": "text", "text": text}}
	contentJSON, err := json.Marshal(contentBlocks)
	if err != nil {
		sse.send(EventTypeError, errorData{Code: "internal", Message: "failed to serialize response"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}
	m, err := o.service.AppendMessage(ctx, tc.tenantID, tc.conversationID, "assistant", contentJSON)
	if err != nil {
		slog.Error("copilot: persist assistant message", "err", err)
		sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to persist response"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}
	sse.send(EventTypeDone, doneData{Reason: "end_turn", MessageID: m.ID.String()})
}

// handleToolUse persists the assistant message with tool_use blocks, emits
// tool_call SSE frames for each tool, records audit, then emits done{tool_use}.
//
// The content block format stored in the DB uses the canonical Anthropic
// tool_use shape (type, id, name, input) which is also the neutral format.
// Both Anthropic and OpenAI providers produce tool accumulators in the same
// form, so the DB format is provider-agnostic.
func (o *Orchestrator) handleToolUse(ctx context.Context, tc turnContext, sse *sseWriter, text string, tools []*toolUseAccum) {
	// Build the content-block array: optional text block + tool_use blocks.
	var contentBlocks []map[string]any
	if strings.TrimSpace(text) != "" {
		contentBlocks = append(contentBlocks, map[string]any{"type": "text", "text": text})
	}
	for _, tb := range tools {
		rawInput := tb.Input.String()
		var inputParsed any
		if err := json.Unmarshal([]byte(rawInput), &inputParsed); err != nil || inputParsed == nil {
			inputParsed = map[string]any{}
		}
		contentBlocks = append(contentBlocks, map[string]any{
			"type":  "tool_use",
			"id":    tb.ID,
			"name":  tb.Name,
			"input": inputParsed,
		})
	}

	contentJSON, err := json.Marshal(contentBlocks)
	if err != nil {
		sse.send(EventTypeError, errorData{Code: "internal", Message: "failed to serialize tool response"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}
	m, err := o.service.AppendMessage(ctx, tc.tenantID, tc.conversationID, "assistant", contentJSON)
	if err != nil {
		slog.Error("copilot: persist tool assistant message", "err", err)
		sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to persist tool call"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}

	// Emit one tool_call SSE frame per tool block.
	for _, tb := range tools {
		rawInput := tb.Input.String()
		var inputRaw json.RawMessage
		if err := json.Unmarshal([]byte(rawInput), &inputRaw); err != nil || len(inputRaw) == 0 {
			inputRaw = json.RawMessage("{}")
		}
		sse.send(EventTypeToolCall, toolCallData{
			ID:    tb.ID,
			Name:  tb.Name,
			Input: inputRaw,
		})
		// Audit the tool request (input REDACTED — may contain PII or identifiers).
		o.recordToolAudit(ctx, tc, tb.Name, m.ID)
	}

	sse.send(EventTypeDone, doneData{Reason: "tool_use", MessageID: m.ID.String()})
}

// recordToolAudit writes a copilot.tool.requested audit row. Tool input is
// intentionally REDACTED; only the tool name and message id are audited.
func (o *Orchestrator) recordToolAudit(ctx context.Context, tc turnContext, toolName string, msgID uuid.UUID) {
	tx, err := o.service.pool.Begin(ctx)
	if err != nil {
		slog.Warn("copilot: audit tx begin", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tid := tc.tenantID
	mid := msgID
	err = audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  tc.actor.UserID,
		ActorType:    tc.actor.Type,
		Action:       "copilot.tool.requested",
		ResourceType: "copilot_message",
		ResourceID:   &mid,
		IP:           tc.actor.IP,
		UserAgent:    tc.actor.UserAgent,
		RequestID:    tc.actor.RequestID,
		Metadata: map[string]any{
			"tool_name":       toolName,
			"tool_input":      "[REDACTED]",
			"conversation_id": tc.conversationID.String(),
		},
	})
	if err != nil {
		slog.Warn("copilot: audit tool.requested", "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Warn("copilot: audit tool.requested commit", "err", err)
	}
}

// buildMessages converts DB copilot.Message values to the neutral ai.Message
// format. The DB stores content as JSON arrays of Anthropic-format content
// blocks, which are identical to ai.ContentBlock in structure and JSON tags.
// Role stays as-is ("user", "assistant", "tool"); each provider remaps as
// needed at the boundary (e.g. Anthropic maps "tool" → "user").
func buildMessages(msgs []Message) []ai.Message {
	out := make([]ai.Message, 0, len(msgs))
	for _, m := range msgs {
		var blocks []ai.ContentBlock
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			// Malformed: wrap as text so the conversation can continue.
			blocks = []ai.ContentBlock{{Type: "text", Text: string(m.Content)}}
		}
		out = append(out, ai.Message{Role: m.Role, Content: blocks})
	}
	return out
}

// buildToolResultContent converts ToolResultInput values from the HTTP request
// body into the neutral tool_result content-block format for the tool turn.
// Sensitive fields are already stripped by the browser before posting; only
// the redacted summary reaches the model.
func buildToolResultContent(results []ToolResultInput) []map[string]any {
	blocks := make([]map[string]any, 0, len(results))
	for _, r := range results {
		var content string
		if r.Error != nil {
			content = fmt.Sprintf("error: %s — %s", r.Error.Code, r.Error.Message)
		} else if r.Output != nil {
			if b, err := json.Marshal(r.Output); err == nil {
				content = string(b)
			}
		}
		if content == "" {
			content = "ok"
		}
		blocks = append(blocks, map[string]any{
			"type":        "tool_result",
			"tool_use_id": r.ToolCallID,
			"content":     content,
		})
	}
	return blocks
}
