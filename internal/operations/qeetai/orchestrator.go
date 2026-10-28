package qeetai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

// systemPrompt is the standing instruction sent to the model on every turn.
// Console context (route, selection) is grounding only — authorization is
// always the server's; the model cannot widen scope from context values.
const systemPrompt = `You are Qeet AI, the AI assistant embedded in the Qeet ID admin console.

You help administrators understand their identity and access setup. In this version you read and explain: you can search users and sessions, review audit logs, simulate an authorization decision, and generate Terraform, SDK snippets and API examples, through the tools available to you.

Key rules:
- You can't make changes in this version. When asked to create, update, disable, delete, reset, assign, grant or rotate anything, say that you can't make changes in this version, explain the steps the administrator takes, and name the console screen where they do it: Users (people, their status and MFA), Organizations, Roles (roles, permissions and assignments), Passwordless (strict MFA), or Applications (OAuth clients and their secrets). Signing keys rotate by deployment, not from the console.
- Use a tool when it helps answer the question; tools run client-side in the operator's browser under their own token, so you can't exceed their authorization.
- Never expose or request secrets (client secrets, private keys, passwords). Secrets surface out-of-band through the console UI.
- Be concise, accurate, and helpful. Prefer short summaries over verbose explanations.
- When the page context includes a selected user, role, or OIDC client, use that as the default subject of the user's request.`

// toolUseAccum holds the streamed fragments for one tool-call block while
// processing the normalized ai.Event stream.
type toolUseAccum struct {
	ID    string
	Name  string
	Input strings.Builder
}

// turnContext is the per-turn input to Orchestrator.Run. pageContext is the
// console's JSON context (route, selection): untrusted grounding text, never
// authorization input.
type turnContext struct {
	tenantID       uuid.UUID
	userID         uuid.UUID
	conversationID uuid.UUID
	pageContext    string
	actor          audit.Actor
}

// ProviderResolver resolves the effective AI provider for a tenant, applying
// BYOK-over-platform fallback (tenant key → platform env key → unconfigured).
// Implemented by *ProviderConfig.
type ProviderResolver interface {
	Resolve(ctx context.Context, tenantID uuid.UUID) (EffectiveConfig, error)
	ProviderFor(ctx context.Context, tenantID uuid.UUID) (ai.Provider, error)
}

// Limits bounds the work of one turn, whoever pays the provider: the most
// recent messages of the conversation sent to the model and their total size,
// and the size of the reply's text.
type Limits struct {
	HistoryMessages int // messages sent; 0: DefaultLimits'
	HistoryBytes    int // their content's bytes; 0: DefaultLimits'
	OutputBytes     int // the reply's text bytes; 0: DefaultLimits'
}

// DefaultLimits are the limits a zero Limits field gets.
var DefaultLimits = Limits{HistoryMessages: 40, HistoryBytes: 256 << 10, OutputBytes: 64 << 10}

// Orchestrator runs streamed model turns and emits SSE frames. It keeps no state
// between requests: history is reloaded from the database and the provider is
// resolved per tenant on every turn.
type Orchestrator struct {
	resolver ProviderResolver
	service  *Service
	limits   Limits
}

// NewOrchestrator returns an Orchestrator that resolves each tenant's provider
// through resolver, stores turns through service and bounds each by limits.
func NewOrchestrator(resolver ProviderResolver, service *Service, limits Limits) *Orchestrator {
	if limits.HistoryMessages <= 0 {
		limits.HistoryMessages = DefaultLimits.HistoryMessages
	}
	if limits.HistoryBytes <= 0 {
		limits.HistoryBytes = DefaultLimits.HistoryBytes
	}
	if limits.OutputBytes <= 0 {
		limits.OutputBytes = DefaultLimits.OutputBytes
	}
	return &Orchestrator{resolver: resolver, service: service, limits: limits}
}

// Run executes one turn: it reloads the recent history, streams the model's
// reply as SSE frames, stores the assistant message and ends with a done
// frame. Tool calls are sent to the client as tool_call frames and audited,
// never run here. The caller must set the SSE headers first.
func (o *Orchestrator) Run(ctx context.Context, tc turnContext, sse *sseWriter) {
	// The recent history, the user turn already persisted by the handler.
	msgs, err := o.service.TurnHistory(ctx, tc.tenantID, tc.userID, tc.conversationID, o.limits.HistoryMessages)
	if err != nil {
		sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to load conversation"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}
	if msgs = recentHistory(msgs, o.limits.HistoryBytes); len(msgs) == 0 {
		sse.send(EventTypeError, errorData{Code: "history_too_long", Message: "this turn is too long to send to the model; start a new conversation"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}

	// Load tool definitions from the embedded manifest.
	toolDefs, err := loadToolDefs()
	if err != nil {
		slog.Error("qeetai: load tools", "err", err)
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

	// Resolve the tenant's effective provider (their own BYOK key, or the
	// platform fallback). The handler has already gated on configured/plan, so
	// an error here is unexpected and terminal for the turn.
	provider, err := o.resolver.ProviderFor(ctx, tc.tenantID)
	if err != nil {
		slog.Error("qeetai: resolve provider", "err", err)
		sse.send(EventTypeError, errorData{Code: "config_error", Message: "AI provider is not available"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}

	sse.send(EventTypeThinking, thinkingData{Text: "Thinking..."})

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	events, errC := provider.Stream(streamCtx, system, aiMsgs, toolDefs)
	text, toolBlocks, ok := collect(events, errC, cancel, sse, o.limits.OutputBytes)
	if !ok {
		return
	}
	if len(toolBlocks) > 0 {
		o.handleToolUse(ctx, tc, sse, text, toolBlocks)
	} else {
		o.handleEndTurn(ctx, tc, sse, text)
	}
}

// recentHistory is the longest tail of msgs within maxBytes of content that
// begins with a person's message, so every tool call in it comes with its
// result. It is empty when the latest turn alone is over maxBytes.
func recentHistory(msgs []Message, maxBytes int) []Message {
	start, size := len(msgs), 0
	for i := len(msgs) - 1; i >= 0; i-- {
		if size += len(msgs[i].Content); size > maxBytes {
			break
		}
		if msgs[i].Role == "user" {
			start = i
		}
	}
	return msgs[start:]
}

// collect reads one turn's stream into its text and tool calls, sending the
// text to sse as it arrives. A tool call must start on the next slot, below
// ai.MaxToolCalls, and its input stay within ai.MaxToolInputBytes; otherwise
// the stream is cancelled and the turn refused. ok is false once collect has
// sent the error and done frames. Text past maxOutput bytes ends the turn
// there, as the model's own token limit would, without its tool calls.
func collect(events <-chan ai.Event, errC <-chan error, cancel context.CancelFunc, sse *sseWriter, maxOutput int) (text string, tools []*toolUseAccum, ok bool) {
	var textBuilder strings.Builder
	fail := func(code, message string) (string, []*toolUseAccum, bool) {
		cancel()
		for range events {
		}
		<-errC
		sse.send(EventTypeError, errorData{Code: code, Message: message})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return "", nil, false
	}

	for ev := range events {
		switch ev.Type {
		case ai.EventTextDelta:
			delta, full := ev.TextDelta, false
			if room := maxOutput - textBuilder.Len(); len(delta) > room {
				for room > 0 && !utf8.RuneStart(delta[room]) {
					room--
				}
				delta, full = delta[:room], true
			}
			if delta != "" {
				textBuilder.WriteString(delta)
				sse.send(EventTypeToken, tokenData{Text: delta})
			}
			if full {
				slog.Info("qeetai: reply cut at the output limit", "bytes", textBuilder.Len())
				cancel()
				for range events {
				}
				<-errC
				return textBuilder.String(), nil, true
			}

		case ai.EventToolCallStart:
			if ev.ToolIndex != len(tools) || len(tools) >= ai.MaxToolCalls {
				slog.Warn("qeetai: model tool call out of bounds", "slot", ev.ToolIndex, "calls", len(tools))
				return fail("model_error", "the model asked for more tool calls than one turn allows")
			}
			tools = append(tools, &toolUseAccum{ID: ev.ToolID, Name: ev.ToolName})

		case ai.EventToolCallDelta:
			if ev.ToolIndex < 0 || ev.ToolIndex >= len(tools) {
				slog.Warn("qeetai: model tool input for no call", "slot", ev.ToolIndex, "calls", len(tools))
				return fail("model_error", "the model sent a tool call it had not started")
			}
			input := &tools[ev.ToolIndex].Input
			if input.Len()+len(ev.ToolInputDelta) > ai.MaxToolInputBytes {
				return fail("model_error", "the model sent a tool call input larger than allowed")
			}
			input.WriteString(ev.ToolInputDelta)

		case ai.EventToolCallStop:
			// No action needed; tool blocks are processed after the loop.

		case ai.EventStop:
			// StopReason is captured implicitly: the path is chosen by
			// len(tools) > 0 after the loop.

		case ai.EventProviderError:
			slog.Error("qeetai: provider stream error", "msg", ev.ErrorMessage)
			return fail("model_error", ev.ErrorMessage)
		}
	}

	// Drain the error channel (buffered, size 1).
	if streamErr := <-errC; streamErr != nil {
		slog.Error("qeetai: stream io error", "err", streamErr)
		sse.send(EventTypeError, errorData{Code: "stream_error", Message: "model stream failed"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return "", nil, false
	}
	return textBuilder.String(), tools, true
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
		slog.Error("qeetai: persist assistant message", "err", err)
		sse.send(EventTypeError, errorData{Code: "db_error", Message: "failed to persist response"})
		sse.send(EventTypeDone, doneData{Reason: "error"})
		return
	}
	sse.send(EventTypeDone, doneData{Reason: "end_turn", MessageID: m.ID.String()})
}

// handleToolUse stores the assistant message with its tool_use blocks, emits a
// tool_call frame and an audit row per tool, then emits done{tool_use}.
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
		slog.Error("qeetai: persist tool assistant message", "err", err)
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

// recordToolAudit writes a qeetai.tool.requested audit row. Tool input is
// intentionally REDACTED; only the tool name and message id are audited.
func (o *Orchestrator) recordToolAudit(ctx context.Context, tc turnContext, toolName string, msgID uuid.UUID) {
	tx, err := o.service.pool.Begin(ctx)
	if err != nil {
		slog.Warn("qeetai: audit tx begin", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tid := tc.tenantID
	mid := msgID
	err = audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  tc.actor.UserID,
		ActorType:    tc.actor.Type,
		Action:       "qeetai.tool.requested",
		ResourceType: "qeetai_message",
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
		slog.Warn("qeetai: audit tool.requested", "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Warn("qeetai: audit tool.requested commit", "err", err)
	}
}

// buildMessages converts stored messages to ai.Message values; stored content
// already has the ai.ContentBlock JSON shape. Roles pass through unchanged and
// each provider remaps them (Anthropic sends "tool" as "user").
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
