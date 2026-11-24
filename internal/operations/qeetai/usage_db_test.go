//go:build integration

package qeetai

import (
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestUsageIsCountedByMonth checks that each turn adds a message and its
// tokens to the organization's month, and no other organization's.
func TestUsageIsCountedByMonth(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, organization, user, _ := conversation(t)
	other := dbtest.Organization(t)
	for _, n := range [][2]int{{100, 20}, {50, 5}} {
		if err := svc.RecordUsage(ctx, organization, n[0], n[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.RecordUsage(ctx, other, 9, 9); err != nil {
		t.Fatal(err)
	}
	h := dbtest.Serve(dbtest.Principal(user, organization), (&Handler{Service: svc, Admin: svc}).Mount)
	var got Usage
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/qeetai/usage", nil), &got)
	m := got.ThisMonth
	if m.Messages != 2 || m.InputTokens != 150 || m.OutputTokens != 25 || got.LastUsedAt == nil || len(got.Months) != 1 {
		t.Errorf("usage %+v, want 2 messages, 150 in and 25 out this month", got)
	}
}

// TestConversationsAreKeptForTheSetTime checks that an organization's setting
// is stored with who changed it, that conversations untouched for longer
// are deleted with their messages and the deletion audited, and that newer
// ones, and an organization that keeps them, are left.
func TestConversationsAreKeptForTheSetTime(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc, organization, user, old := conversation(t)
	fresh, err := svc.CreateConversation(ctx, organization, user, CreateConversationInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, keeper, keeperUser, kept := conversation(t)
	for _, id := range []any{old, kept} {
		if _, err := pool.Exec(ctx, `UPDATE qeetai.conversations SET updated_at = NOW() - INTERVAL '40 days' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	h := dbtest.Serve(dbtest.Principal(user, organization), (&Handler{Service: svc, Admin: svc}).Mount)
	path := "/organizations/" + organization.String() + "/qeetai/settings"
	if rec := dbtest.Do(t, h, http.MethodPut, path, map[string]any{"conversation_retention_days": 0}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("keep for 0 days: %d, want 422", rec.Code)
	}
	var set Settings
	rec := dbtest.Do(t, h, http.MethodPut, path, map[string]any{"conversation_retention_days": 30})
	dbtest.Decode(t, rec, &set)
	if rec.Code != http.StatusOK || set.ConversationRetentionDays == nil || *set.ConversationRetentionDays != 30 || set.UpdatedBy == nil || *set.UpdatedBy != user {
		t.Fatalf("set 30 days: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.SetSettings(ctx, keeper, nil, audit.Actor{UserID: &keeperUser, Type: "user"}); err != nil {
		t.Fatal(err)
	}

	n, err := PurgeExpiredConversations(ctx, pool)
	if err != nil || n != 1 {
		t.Fatalf("purge: %d, %v; want the one old conversation", n, err)
	}
	if left := dbtest.Count(t, `SELECT count(*) FROM qeetai.conversations WHERE id = ANY($1)`, []any{old, fresh.ID, kept}); left != 2 {
		t.Errorf("%d conversations left, want the fresh one and the keeper's", left)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'qeetai.conversations_purged' AND (metadata->>'deleted')::int = 1`, organization); n != 1 {
		t.Errorf("%d purges audited, want one", n)
	}
}
