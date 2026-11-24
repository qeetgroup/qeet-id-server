//go:build integration

package passkey

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestBeginLoginAnswersAlike checks that starting a passkey sign-in answers
// the same, in shape, for an account with a passkey, one without, an unknown
// address and no address.
func TestBeginLoginAnswersAlike(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	organization := dbtest.Organization(t)
	withPasskey, without := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key) VALUES ($1, $2, $3)
	`, withPasskey.ID, []byte(dbtest.Unique("credential")), []byte("key")); err != nil {
		t.Fatalf("passkey: %v", err)
	}

	shapes := map[string]string{}
	for name, email := range map[string]string{
		"account with a passkey":    withPasskey.Email,
		"account without a passkey": without.Email,
		"unknown address":           dbtest.Unique("nobody") + "@example.test",
		"no address":                "",
	} {
		id, options, err := svc.BeginLogin(ctx, email)
		if err != nil || id == uuid.Nil || options == nil {
			t.Errorf("%s: %v, %v, %v; want a ceremony", name, id, options, err)
			continue
		}
		raw, err := json.Marshal(options.Response)
		if err != nil {
			t.Fatalf("encode options: %v", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("decode options: %v", err)
		}
		delete(fields, "challenge")
		shape, _ := json.Marshal(fields)
		shapes[name] = string(shape)
	}
	for name, shape := range shapes {
		if shape != shapes["no address"] {
			t.Errorf("%s answers %s, want %s as for no address", name, shape, shapes["no address"])
		}
	}
}
