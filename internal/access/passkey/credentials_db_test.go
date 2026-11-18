//go:build integration

package passkey

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPasskeyChangesAreAuditedAndTold checks that adding, renaming and
// removing a passkey are each recorded in the organization the session is in,
// naming the passkey, and that the account holder is emailed when one is added
// or removed, but not when a removal is refused or another's passkey is asked
// for.
func TestPasskeyChangesAreAuditedAndTold(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := signInService(t)
	mail := &dbtest.Mailbox{}
	svc.SetSender(mail)
	organization := dbtest.Organization(t)
	a, other := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user", IP: "192.0.2.7", RequestID: "req-passkey"}, OrganizationID: &organization}
	type record struct {
		PasskeyID    uuid.UUID `json:"passkey_id"`
		Name         string    `json:"name"`
		PreviousName string    `json:"previous_name"`
	}
	audited := func(action string) []record {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND resource_type = 'user' AND resource_id = $3
			  AND actor_user_id = $3 AND ip = '192.0.2.7' AND request_id = 'req-passkey'
			ORDER BY created_at`, organization, action, a.ID)
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		defer rows.Close()
		var out []record
		for rows.Next() {
			var raw []byte
			var r record
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}

	registerAs(t, svc, a.ID, "Laptop", who)
	creds, err := svc.List(ctx, a.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("passkeys %+v, %v; want one", creds, err)
	}
	id := creds[0].ID
	if got := audited("passkey.registered"); len(got) != 1 || got[0].PasskeyID != id || got[0].Name != "Laptop" {
		t.Errorf("passkey.registered records %+v, want one naming the Laptop passkey", got)
	}
	added := mail.Last(t)
	if added.To != a.Email || !strings.Contains(added.Subject, "added") || !strings.Contains(added.Body, "Laptop") || added.HTML == "" {
		t.Errorf("notice %+v, want one to %s that the Laptop passkey was added", added, a.Email)
	}

	if _, err := svc.Rename(ctx, id, a.ID, "Work laptop", who); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := audited("passkey.renamed"); len(got) != 1 || got[0].Name != "Work laptop" || got[0].PreviousName != "Laptop" {
		t.Errorf("passkey.renamed records %+v, want one from Laptop to Work laptop", got)
	}
	if _, err := svc.Rename(ctx, id, other.ID, "Mine now", who); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("rename another's passkey: %v, want %v", err, errs.ErrNotFound)
	}

	sent := mail.Len()
	if err := svc.Delete(ctx, id, a.ID, who); !errors.Is(err, errs.ErrAuthLastSignInMethod) {
		t.Fatalf("remove the only way to sign in: %v, want %v", err, errs.ErrAuthLastSignInMethod)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.sign_in_method_removal_refused' AND resource_id = $2`, organization, a.ID); n != 1 {
		t.Errorf("%d refusals recorded in the organization, want 1", n)
	}
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	if err := svc.Delete(ctx, id, other.ID, who); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("remove another's passkey: %v, want %v", err, errs.ErrNotFound)
	}
	if mail.Len() != sent {
		t.Error("a refused removal emailed the account holder")
	}
	if err := svc.Delete(ctx, id, a.ID, who); err != nil {
		t.Fatalf("remove a passkey beside a password: %v", err)
	}
	if got := audited("passkey.deleted"); len(got) != 1 || got[0].PasskeyID != id || got[0].Name != "Work laptop" {
		t.Errorf("passkey.deleted records %+v, want one naming the Work laptop passkey", got)
	}
	removed := mail.Last(t)
	if removed.To != a.Email || !strings.Contains(removed.Subject, "removed") || !strings.Contains(removed.Body, "Work laptop") {
		t.Errorf("notice %+v, want one to %s that the Work laptop passkey was removed", removed, a.Email)
	}
}
