//go:build integration

package invite

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestInviteRoleMustBelongToTheTenant checks that an invitation can carry only
// a role of the inviting tenant, answering another tenant's role as a missing
// one, and that the database refuses to store one carrying another tenant's.
func TestInviteRoleMustBelongToTheTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	h, _ := newHandler(t)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	roleA := dbtest.Role(t, tenantA, "users:write")
	adminB := dbtest.User(t, tenantB, tenantB)
	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), h.MountAuthed)

	type answer struct {
		Status                int
		Code, Message, Detail string
	}
	answers := map[string]answer{}
	for name, role := range map[string]uuid.UUID{"another tenant's role": roleA, "a missing role": uuid.New()} {
		email := dbtest.Unique("invitee") + "@example.test"
		rec := dbtest.Do(t, asB, http.MethodPost, "/invites", map[string]any{"email": email, "role_id": role})
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
				Detail  string `json:"detail"`
			} `json:"error"`
		}
		dbtest.Decode(t, rec, &body)
		answers[name] = answer{rec.Code, body.Error.Code, body.Error.Message, body.Error.Detail}
		if rec.Code != http.StatusNotFound || body.Error.Code != errs.CodeNotFound {
			t.Errorf("invite with %s: %d %s, want 404 %s (%s)", name, rec.Code, body.Error.Code, errs.CodeNotFound, rec.Body.String())
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM tenant.invites WHERE email = $1`, email); n != 0 {
			t.Errorf("invite with %s was stored", name)
		}
	}
	if answers["another tenant's role"] != answers["a missing role"] {
		t.Errorf("another tenant's role is answered %+v, a missing one %+v", answers["another tenant's role"], answers["a missing role"])
	}

	// Below the service too: the database won't store such an invitation.
	_, hash, err := codes.URLToken()
	if err != nil {
		t.Fatal(err)
	}
	_, err = dbtest.Pool(t).Exec(ctx, `
		INSERT INTO tenant.invites (tenant_id, email, role_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 day')
	`, tenantB, dbtest.Unique("invitee")+"@example.test", roleA, hash)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("an invitation carrying another tenant's role was stored: %v, want a foreign key violation", err)
	}
}
