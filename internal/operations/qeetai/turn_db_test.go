//go:build integration

package qeetai

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// conversation creates a conversation of a new user in a new organization.
func conversation(t *testing.T) (svc *Service, organization, user, conv uuid.UUID) {
	t.Helper()
	svc = NewService(dbtest.Pool(t))
	organization = dbtest.Organization(t)
	user = dbtest.User(t, organization).ID
	c, err := svc.CreateConversation(dbtest.Context(t), organization, user, CreateConversationInput{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, organization, user, c.ID
}

// TestOneTurnAtATime checks that a conversation answers one turn at a time,
// that a turn ended frees it, that a turn left unfinished past the longest a
// turn may run is taken over, and that the turn it took over from can't free
// the one that took over.
func TestOneTurnAtATime(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, organization, _, conv := conversation(t)
	_, otherOrganization, _, otherConv := conversation(t)

	release, err := svc.BeginTurn(ctx, organization, conv)
	if err != nil {
		t.Fatalf("first turn: %v", err)
	}
	if _, err := svc.BeginTurn(ctx, organization, conv); !errors.Is(err, errs.ErrQeetAITurnInProgress) {
		t.Errorf("a second turn while the first runs: %v, want %v", err, errs.ErrQeetAITurnInProgress)
	}
	otherRelease, err := svc.BeginTurn(ctx, otherOrganization, otherConv)
	if err != nil {
		t.Errorf("a turn of another conversation: %v, want it to run", err)
	} else {
		otherRelease()
	}
	if _, err := svc.BeginTurn(ctx, otherOrganization, conv); err == nil {
		t.Error("another organisation began a turn of this conversation")
	}
	release()
	again, err := svc.BeginTurn(ctx, organization, conv)
	if err != nil {
		t.Fatalf("a turn once the first ended: %v", err)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE qeetai.conversation_turns SET started_at = started_at - $3::interval
		WHERE conversation_id = $1 AND organization_id = $2`, conv, organization, fmt.Sprintf("%d seconds", int((turnTimeout+2*60e9)/1e9))); err != nil {
		t.Fatal(err)
	}
	takeover, err := svc.BeginTurn(ctx, organization, conv)
	if err != nil {
		t.Fatalf("a turn after one was left unfinished: %v, want it to take over", err)
	}
	again()
	if _, err := svc.BeginTurn(ctx, organization, conv); !errors.Is(err, errs.ErrQeetAITurnInProgress) {
		t.Errorf("the unfinished turn ended the one that took over: %v", err)
	}
	takeover()
}

// TestTurnHistoryIsTheLatestMessages checks that a turn reads only the latest
// messages of its conversation, oldest first, and only its owner's.
func TestTurnHistoryIsTheLatestMessages(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, organization, user, conv := conversation(t)
	for i := range 5 {
		content, _ := json.Marshal([]map[string]any{{"type": "text", "text": fmt.Sprint(i)}})
		if _, err := svc.AppendMessage(ctx, organization, conv, "user", content); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := svc.TurnHistory(ctx, organization, user, conv, 3)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range msgs {
		var blocks []struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(m.Content, &blocks)
		got = append(got, blocks[0].Text)
	}
	if fmt.Sprint(got) != "[2 3 4]" {
		t.Errorf("history %v, want the latest three, oldest first: [2 3 4]", got)
	}
	if _, err := svc.TurnHistory(ctx, organization, uuid.New(), conv, 3); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("another user's history: %v, want not found", err)
	}
}
