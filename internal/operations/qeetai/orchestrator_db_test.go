//go:build integration

package qeetai

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// stubProvider replays events as the model's reply to every turn.
type stubProvider struct{ events []ai.Event }

func (p stubProvider) Stream(ctx context.Context, _ string, _ []ai.Message, _ []ai.ToolDef) (<-chan ai.Event, <-chan error) {
	out, errC, _ := fakeStream(ctx, p.events, false)
	return out, errC
}

// providerResolver hands every organization the same provider.
type providerResolver struct{ provider ai.Provider }

func (r providerResolver) Resolve(context.Context, uuid.UUID) (EffectiveConfig, error) {
	return EffectiveConfig{Source: SourceOrganization}, nil
}

func (r providerResolver) ProviderFor(context.Context, uuid.UUID) (ai.Provider, error) {
	return r.provider, nil
}

// TestToolsNotOfferedNeverReachTheClient checks that a tool call the model was
// never offered (a change tool such as delete_user) is sent to no client and
// stored nowhere, is recorded as refused, and that the model is told in the
// stored reply, while an offered tool beside it still goes to the client.
func TestToolsNotOfferedNeverReachTheClient(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, organization, user, conv := conversation(t)
	content, _ := json.Marshal([]map[string]any{{"type": "text", "text": "delete Ann"}})
	if _, err := svc.AppendMessage(ctx, organization, conv, "user", content); err != nil {
		t.Fatal(err)
	}
	call := func(slot int, id, name string) []ai.Event {
		return []ai.Event{
			{Type: ai.EventToolCallStart, ToolIndex: slot, ToolID: id, ToolName: name},
			{Type: ai.EventToolCallDelta, ToolIndex: slot, ToolInputDelta: `{"user_id":"ann"}`},
		}
	}
	events := append([]ai.Event{{Type: ai.EventTextDelta, TextDelta: "Deleting Ann."}}, call(0, "a", "delete_user")...)
	events = append(events, call(1, "b", "search_users")...)
	events = append(events, ai.Event{Type: ai.EventStop, StopReason: "tool_use"})

	o := NewOrchestrator(providerResolver{stubProvider{events}}, svc, Limits{})
	rec := httptest.NewRecorder()
	o.Run(ctx, turnContext{organizationID: organization, userID: user, conversationID: conv,
		actor: audit.Actor{UserID: &user, Type: "user"}}, newSSEWriter(rec))
	frames := rec.Body.String()

	if strings.Contains(frames, "delete_user\",\"input") || strings.Count(frames, "event: tool_call") != 1 {
		t.Errorf("frames %s\nwant one tool_call, for search_users only", frames)
	}
	_, msgs, err := svc.GetConversation(ctx, organization, user, conv)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []ai.ContentBlock
	if err := json.Unmarshal(msgs[len(msgs)-1].Content, &blocks); err != nil {
		t.Fatal(err)
	}
	var calls []string
	for _, b := range blocks {
		if b.Type == "tool_use" {
			calls = append(calls, b.Name)
		}
	}
	if len(calls) != 1 || calls[0] != "search_users" {
		t.Errorf("stored calls %v, want search_users's only", calls)
	}
	if !strings.Contains(blocks[0].Text, "delete_user") || !strings.Contains(frames, "delete_user") {
		t.Errorf("the model and the person were not told delete_user is unavailable: stored %+v", blocks)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1
		AND action = 'qeetai.tool.refused' AND metadata->>'tool_name' = 'delete_user'`, organization); n != 1 {
		t.Errorf("%d refusals recorded, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1
		AND action = 'qeetai.tool.requested' AND metadata->>'tool_name' = 'delete_user'`, organization); n != 0 {
		t.Errorf("delete_user was recorded as requested of the client")
	}
}

// TestATurnOfOnlyRefusedToolsEndsTheTurn checks that when every call is to a
// tool not offered, the turn ends with the model's text and the refusal, and
// no tool_call at all.
func TestATurnOfOnlyRefusedToolsEndsTheTurn(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, organization, user, conv := conversation(t)
	o := NewOrchestrator(providerResolver{stubProvider{[]ai.Event{
		{Type: ai.EventToolCallStart, ToolIndex: 0, ToolID: "a", ToolName: "reset_user_mfa"},
		{Type: ai.EventStop, StopReason: "tool_use"},
	}}}, svc, Limits{})
	content, _ := json.Marshal([]map[string]any{{"type": "text", "text": "reset Ann"}})
	if _, err := svc.AppendMessage(ctx, organization, conv, "user", content); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	o.Run(ctx, turnContext{organizationID: organization, userID: user, conversationID: conv,
		actor: audit.Actor{UserID: &user, Type: "user"}}, newSSEWriter(rec))
	frames := rec.Body.String()
	if strings.Contains(frames, "event: tool_call") || !strings.Contains(frames, `"reason":"end_turn"`) {
		t.Errorf("frames %s\nwant no tool_call and done{end_turn}", frames)
	}
}
