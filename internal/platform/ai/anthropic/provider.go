package anthropic

import (
	"context"

	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
)

// Provider wraps Client to satisfy the ai.Provider interface. It converts the
// neutral ai.Message/ai.ToolDef formats to Anthropic wire format, calls the
// underlying streaming API, and maps ParsedEvent values to ai.Event values.
//
// Construct via NewProvider and pass to the copilot orchestrator.
type Provider struct {
	client *Client
}

// NewProvider returns an ai.Provider backed by the given Anthropic Client.
func NewProvider(c *Client) *Provider {
	return &Provider{client: c}
}

// Stream implements ai.Provider. It translates the neutral conversation history
// and tool definitions to Anthropic wire format, streams the response, and
// emits normalized ai.Event values. Blocking until the stream ends or ctx is
// cancelled.
func (p *Provider) Stream(ctx context.Context, system string, messages []ai.Message, tools []ai.ToolDef) (<-chan ai.Event, <-chan error) {
	req := MessagesRequest{
		System:   system,
		Messages: toAnthropicMessages(messages),
		Tools:    toAnthropicTools(tools),
	}

	rawEvents, rawErrC := p.client.Stream(ctx, req)

	out := make(chan ai.Event, 64)
	errC := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errC)

		// toolCallCount tracks how many tool_use blocks have started so far,
		// providing a stable 0-based ToolIndex for each new block.
		var (
			toolCallCount    int
			inToolBlock      bool
			currentToolIndex int
		)

		for ev := range rawEvents {
			switch ev.Type {
			case EventContentBlockStart:
				if ev.ToolUseID != "" {
					// New tool_use block: assign the next slot index.
					currentToolIndex = toolCallCount
					toolCallCount++
					inToolBlock = true
					out <- ai.Event{
						Type:      ai.EventToolCallStart,
						ToolIndex: currentToolIndex,
						ToolID:    ev.ToolUseID,
						ToolName:  ev.ToolUseName,
					}
				}

			case EventContentBlockDelta:
				if ev.TextDelta != "" {
					out <- ai.Event{Type: ai.EventTextDelta, TextDelta: ev.TextDelta}
				}
				if ev.InputJSONDelta != "" && inToolBlock {
					out <- ai.Event{
						Type:           ai.EventToolCallDelta,
						ToolIndex:      currentToolIndex,
						ToolInputDelta: ev.InputJSONDelta,
					}
				}

			case EventContentBlockStop:
				if inToolBlock {
					out <- ai.Event{Type: ai.EventToolCallStop, ToolIndex: currentToolIndex}
					inToolBlock = false
				}

			case EventMessageDelta:
				if ev.StopReason != "" {
					out <- ai.Event{Type: ai.EventStop, StopReason: ev.StopReason}
				}

			case EventError:
				out <- ai.Event{Type: ai.EventProviderError, ErrorMessage: ev.ErrorMessage}
			}
		}

		if err := <-rawErrC; err != nil {
			errC <- err
		}
	}()

	return out, errC
}

// toAnthropicMessages converts the neutral ai.Message slice to Anthropic wire
// format. "tool" role is remapped to "user" — Anthropic's convention for
// tool_result turns. Content blocks map field-for-field (same JSON shape).
func toAnthropicMessages(msgs []ai.Message) []Message {
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		role := m.Role
		if role == "tool" {
			role = "user"
		}
		blocks := make([]ContentBlock, 0, len(m.Content))
		for _, cb := range m.Content {
			blocks = append(blocks, ContentBlock{
				Type:      cb.Type,
				Text:      cb.Text,
				ID:        cb.ID,
				Name:      cb.Name,
				Input:     cb.Input,
				ToolUseID: cb.ToolUseID,
				Content:   cb.Content,
			})
		}
		out = append(out, Message{Role: role, Content: blocks})
	}
	return out
}

// toAnthropicTools converts the neutral ai.ToolDef slice to Anthropic ToolDef
// format. The JSON Schema in InputSchema is identical to Anthropic's field.
func toAnthropicTools(tools []ai.ToolDef) []ToolDef {
	out := make([]ToolDef, 0, len(tools))
	for _, t := range tools {
		out = append(out, ToolDef{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return out
}
