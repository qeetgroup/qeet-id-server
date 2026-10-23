//go:build integration

package dbtest

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Account is a user created by User.
type Account struct {
	ID    uuid.UUID
	Email string
}

// Unique returns prefix followed by a short random suffix, for slugs, names
// and emails that must not collide with another test's.
func Unique(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
}

// Tenant creates an active tenant and returns its id.
func Tenant(t testing.TB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	slug := Unique("org")
	if err := Pool(t).QueryRow(context.Background(), `
		INSERT INTO tenant.tenants (slug, name) VALUES ($1, $1) RETURNING id
	`, slug).Scan(&id); err != nil {
		t.Fatalf("dbtest: create tenant: %v", err)
	}
	return id
}

// User creates an active user whose home is tenant home (uuid.Nil: none) and
// gives them a role in each tenant of memberOf.
func User(t testing.TB, home uuid.UUID, memberOf ...uuid.UUID) Account {
	t.Helper()
	var homeArg any
	if home != uuid.Nil {
		homeArg = home
	}
	a := Account{Email: Unique("user") + "@example.test"}
	if err := Pool(t).QueryRow(context.Background(), `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, homeArg, a.Email).Scan(&a.ID); err != nil {
		t.Fatalf("dbtest: create user: %v", err)
	}
	for _, tenant := range memberOf {
		Assign(t, a.ID, tenant, Role(t, tenant))
	}
	return a
}

// SetPassword gives the user a password credential for plain.
func SetPassword(t testing.TB, userID uuid.UUID, plain string) {
	t.Helper()
	hash, err := password.Hash(plain)
	if err != nil {
		t.Fatalf("dbtest: hash password: %v", err)
	}
	if _, err := Pool(t).Exec(context.Background(), `
		INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)
	`, userID, hash); err != nil {
		t.Fatalf("dbtest: set password: %v", err)
	}
}

// Role creates a non-system role in tenant holding the given permission keys
// and returns its id.
func Role(t testing.TB, tenant uuid.UUID, permissions ...string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	if err := Pool(t).QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, $2) RETURNING id
	`, tenant, Unique("role")).Scan(&id); err != nil {
		t.Fatalf("dbtest: create role: %v", err)
	}
	for _, key := range permissions {
		if _, err := Pool(t).Exec(ctx, `
			WITH p AS (
				INSERT INTO rbac.permissions (key) VALUES ($2)
				ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id
			)
			INSERT INTO rbac.role_permissions (role_id, permission_id) SELECT $1, id FROM p
		`, id, key); err != nil {
			t.Fatalf("dbtest: grant %s: %v", key, err)
		}
	}
	return id
}

// Assign gives the user role in tenant.
func Assign(t testing.TB, userID, tenant, role uuid.UUID) {
	t.Helper()
	if _, err := Pool(t).Exec(context.Background(), `
		INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)
	`, userID, tenant, role); err != nil {
		t.Fatalf("dbtest: assign role: %v", err)
	}
}

// Count runs a single-value count query.
func Count(t testing.TB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := Pool(t).QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("dbtest: count: %v", err)
	}
	return n
}

// Issuer returns a token issuer with a fresh ES256 signing key.
func Issuer(t testing.TB) *tokens.Issuer {
	t.Helper()
	key, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("dbtest: signing key: %v", err)
	}
	issuer, err := tokens.NewIssuer(key, "qeet", "qeet", 15*time.Minute, 720*time.Hour)
	if err != nil {
		t.Fatalf("dbtest: issuer: %v", err)
	}
	return issuer
}

// Mailbox is a notifier.Sender that keeps the messages it is asked to send.
type Mailbox struct {
	mu   sync.Mutex
	sent []notifier.Message
}

// Send records m.
func (b *Mailbox) Send(_ context.Context, m notifier.Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, m)
	return nil
}

// Last returns the most recent message, failing t when nothing was sent.
func (b *Mailbox) Last(t testing.TB) notifier.Message {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == 0 {
		t.Fatal("dbtest: no message was sent")
	}
	return b.sent[len(b.sent)-1]
}

// Len returns how many messages were sent.
func (b *Mailbox) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.sent)
}
