//go:build integration

package invite

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestInviteLookupOffersWhatAcceptAllows checks that the preview offers a
// password only where accepting with one is allowed, and a passkey only where
// the organization allows passkeys.
func TestInviteLookupOffersWhatAcceptAllows(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h, _ := newHandler(t)
	h.Service.methods = policies(t)
	for _, tc := range []struct {
		name              string
		password, passkey bool
	}{
		{"passwords on", true, false},
		{"passwords off", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			organization := dbtest.Organization(t)
			if _, err := pool.Exec(ctx, `INSERT INTO organization.auth_policy (organization_id, password_enabled, passkey_enabled) VALUES ($1, $2, $3)`,
				organization, tc.password, tc.passkey); err != nil {
				t.Fatalf("policy: %v", err)
			}
			_, token, err := h.Service.Create(ctx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("invitee") + "@example.test"}, audit.Actor{})
			if err != nil {
				t.Fatalf("invite: %v", err)
			}
			preview, err := h.Service.Lookup(ctx, token)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if preview.Methods.Password != tc.password || preview.Methods.Passkey != tc.passkey {
				t.Errorf("lookup offers %+v, want password %v and passkey %v", preview.Methods, tc.password, tc.passkey)
			}
			_, err = h.Service.Accept(ctx, AcceptInput{Token: token, Password: testPassword}, audit.Actor{})
			if accepted := err == nil; accepted != preview.Methods.Password {
				t.Errorf("accept with a password: %v, but lookup offered a password: %v", err, preview.Methods.Password)
			}
		})
	}
}
