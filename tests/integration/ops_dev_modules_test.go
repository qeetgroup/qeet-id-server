//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	principal "github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	notification "github.com/qeetgroup/qeet-id-server/internal/operations/notifications"
)

// Notifications: the in-app inbox tracks unread count and MarkAllRead clears it.
func TestNotificationService_InboxUnreadMarkRead(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("ntf"))
	u := createTenantUser(t, ctx, tid, uniqueSlug("nuser")+"@example.com")
	svc := notification.NewService(testPool)

	if err := svc.Notify(ctx, tid, u, "security", "New login", "from a new device", "/security"); err != nil {
		t.Fatalf("Notify (1): %v", err)
	}
	if err := svc.Notify(ctx, tid, u, "security", "MFA enabled", "", "/security/mfa"); err != nil {
		t.Fatalf("Notify (2): %v", err)
	}

	items, unread, err := svc.List(ctx, u, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 || unread != 2 {
		t.Fatalf("items=%d unread=%d, want 2/2", len(items), unread)
	}

	if err := svc.MarkAllRead(ctx, u); err != nil {
		t.Fatalf("MarkAllRead: %v", err)
	}
	items, unread, err = svc.List(ctx, u, 50)
	if err != nil {
		t.Fatalf("List (after read): %v", err)
	}
	if len(items) != 2 || unread != 0 {
		t.Fatalf("after MarkAllRead items=%d unread=%d, want 2/0", len(items), unread)
	}
}

// Service accounts: client_credentials issues a token for the right secret and
// rejects a wrong secret or an unknown client.
func TestPrincipalService_ClientCredentials(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("svc"))
	svc := principal.NewService(testPool, mustIssuer())

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	p, secret, err := svc.Create(ctx, tx, principal.CreateInput{TenantID: tid, Name: "ci-bot", Scopes: []string{"users:read"}})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("Create: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	resp, err := svc.IssueClientCredentials(ctx, p.ID.String(), secret)
	if err != nil {
		t.Fatalf("IssueClientCredentials (valid): %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected a non-empty access token")
	}

	if _, err := svc.IssueClientCredentials(ctx, p.ID.String(), "wrong-secret"); err == nil {
		t.Fatal("a wrong client secret should be rejected")
	}
	if _, err := svc.IssueClientCredentials(ctx, uuid.New().String(), secret); err == nil {
		t.Fatal("an unknown client id should be rejected")
	}
}
