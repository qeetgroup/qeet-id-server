//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An invited person without an account can accept with a passkey instead of a
// password: the acceptance screen looks the invitation up to learn whether the
// organisation allows passkeys, and the passkey ceremony creates the account,
// grants the invited role and accepts the invitation in one step, then signs
// the person in. The email and organisation come from the invitation; a failed,
// expired, abandoned or replayed ceremony leaves the invitation pending.

type invitePasskeyFixture struct {
	invites  *invite.Service
	passkeys *passkey.Service
	router   http.Handler
	tenantID uuid.UUID
	roleID   uuid.UUID
}

func newInvitePasskeyFixture(t *testing.T, ctx context.Context) *invitePasskeyFixture {
	t.Helper()
	f := &invitePasskeyFixture{tenantID: createTenant(t, ctx, uniqueSlug("invpk"))}
	if err := testPool.QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name, description, is_system) VALUES ($1, $2, 'invited', FALSE) RETURNING id`,
		f.tenantID, uniqueSlug("invited")).Scan(&f.roleID); err != nil {
		t.Fatalf("create role: %v", err)
	}
	methods := authpolicy.NewService(testPool)
	f.invites = invite.NewService(testPool, &captureSender{}, time.Hour, "http://app.test")
	f.invites.SetPasswordRules(methods)
	f.invites.SetAcceptMethods(methods)
	authSvc, _ := newAuth()
	f.passkeys = newPasskeySvcWithAuth(t, authSvc)
	f.passkeys.SetMethodPolicy(methods)
	f.passkeys.SetInvitations(f.invites)

	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		(&invite.Handler{Service: f.invites, AuthService: authSvc, Validate: validator.New()}).MountPublic(r)
		(&passkey.Handler{Service: f.passkeys}).MountPublic(r)
	})
	f.router = r
	return f
}

func (f *invitePasskeyFixture) invite(t *testing.T, ctx context.Context) (email, token string, id uuid.UUID) {
	t.Helper()
	email = uniqueSlug("invitee") + "@example.com"
	role := f.roleID
	inv, raw, err := f.invites.Create(ctx, invite.CreateInput{TenantID: f.tenantID, Email: email, RoleID: &role}, nil)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	return email, raw, inv.ID
}

func (f *invitePasskeyFixture) post(path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/154")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// begin starts the ceremony over HTTP and returns its id and the attestation
// a fresh authenticator answers it with (its credential remembered by a, so it
// can sign in afterwards).
func (f *invitePasskeyFixture) begin(t *testing.T, token string, a *virtualwebauthn.Authenticator, c virtualwebauthn.Credential) (uuid.UUID, json.RawMessage) {
	t.Helper()
	rr := f.post("/v1/invites/accept/passkey/begin", map[string]string{"token": token, "display_name": "Ada Lovelace"})
	if rr.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		SessionID uuid.UUID `json:"session_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	options, err := virtualwebauthn.ParseAttestationOptions(rr.Body.String())
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	a.Options.UserHandle = []byte(options.UserID)
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	return out.SessionID, json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, *a, c, *options))
}

func (f *invitePasskeyFixture) finish(sessionID uuid.UUID, attestation json.RawMessage) *httptest.ResponseRecorder {
	return f.post("/v1/invites/accept/passkey/finish", map[string]any{"session_id": sessionID, "credential": attestation})
}

func usersWithEmail(t *testing.T, ctx context.Context, email string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM "user".users WHERE email = $1`, email).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func inviteStatus(t *testing.T, ctx context.Context, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := testPool.QueryRow(ctx, `SELECT status FROM tenant.invites WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("read invite: %v", err)
	}
	return s
}

// TestAcceptInvitationWithPasskey covers: the lookup offers a passkey; the
// ceremony creates the account in the inviting organisation with that passkey
// and no password, verified, holding the invited role; the invitation is
// accepted; the invitee is signed in and can sign in again with the passkey;
// submitting the ceremony again creates nothing; the accepted invitation is
// refused afterwards.
func TestAcceptInvitationWithPasskey(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newInvitePasskeyFixture(t, ctx)
	email, token, inviteID := f.invite(t, ctx)

	rr := f.post("/v1/invites/lookup", map[string]string{"token": token})
	var preview invite.InvitationPreview
	_ = json.Unmarshal(rr.Body.Bytes(), &preview)
	if rr.Code != http.StatusOK || preview.Email != email || !preview.Methods.Passkey || !preview.Methods.Password || preview.AccountExists {
		t.Fatalf("lookup: %d %s", rr.Code, rr.Body.String())
	}

	a := virtualwebauthn.NewAuthenticator()
	c := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	sid, attestation := f.begin(t, token, &a, c)
	rr = f.finish(sid, attestation)
	if rr.Code != http.StatusOK {
		t.Fatalf("finish: %d %s", rr.Code, rr.Body.String())
	}
	var pair struct {
		UserID      uuid.UUID `json:"user_id"`
		TenantID    uuid.UUID `json:"tenant_id"`
		AccessToken string    `json:"access_token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &pair)
	if pair.AccessToken == "" || pair.TenantID != f.tenantID {
		t.Fatalf("not signed in to the inviting organisation: %s", rr.Body.String())
	}

	var (
		tenant                        uuid.UUID
		verified, hasPassword, inRole bool
		passkeys                      int
	)
	if err := testPool.QueryRow(ctx, `
		SELECT u.tenant_id, u.email_verified_at IS NOT NULL,
		       EXISTS (SELECT 1 FROM auth.password_credentials p WHERE p.user_id = u.id),
		       (SELECT count(*) FROM auth.passkey_credentials k WHERE k.user_id = u.id),
		       EXISTS (SELECT 1 FROM rbac.user_roles r WHERE r.user_id = u.id AND r.tenant_id = $2 AND r.role_id = $3)
		FROM "user".users u WHERE u.id = $1`, pair.UserID, f.tenantID, f.roleID).
		Scan(&tenant, &verified, &hasPassword, &passkeys, &inRole); err != nil {
		t.Fatalf("read account: %v", err)
	}
	if tenant != f.tenantID || !verified || hasPassword || passkeys != 1 || !inRole {
		t.Errorf("account: tenant %v verified %v password %v passkeys %d role %v; want the inviting organisation, verified, no password, one passkey, the invited role",
			tenant, verified, hasPassword, passkeys, inRole)
	}
	if got := inviteStatus(t, ctx, inviteID); got != "accepted" {
		t.Errorf("invitation is %q, want accepted", got)
	}

	// The passkey signs the new account in.
	a.AddCredential(c)
	loginSID, assertion, err := f.passkeys.BeginLogin(ctx, "")
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	assertJSON, _ := json.Marshal(assertion)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(assertJSON))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	login, err := f.passkeys.FinishLogin(ctx, loginSID, json.RawMessage(virtualwebauthn.CreateAssertionResponse(rp, a, c, *assertionOptions)), "203.0.113.7", "test")
	if err != nil || login.UserID != pair.UserID {
		t.Fatalf("sign in with the invitation passkey: %v", err)
	}

	if rr := f.finish(sid, attestation); rr.Code < 400 {
		t.Errorf("the ceremony finished twice: %d %s", rr.Code, rr.Body.String())
	}
	if n := usersWithEmail(t, ctx, email); n != 1 {
		t.Errorf("%d accounts for the invited address, want 1", n)
	}
	if rr := f.post("/v1/invites/lookup", map[string]string{"token": token}); errorCode(t, rr) != errs.CodeInviteInvalid {
		t.Errorf("lookup of an accepted invitation: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.post("/v1/invites/accept/passkey/begin", map[string]string{"token": token}); errorCode(t, rr) != errs.CodeInviteInvalid {
		t.Errorf("begin on an accepted invitation: %d %s", rr.Code, rr.Body.String())
	}
}

// TestAcceptInvitationWithPasskeyRefusals: each refusal creates no account and
// leaves the invitation as it was.
func TestAcceptInvitationWithPasskeyRefusals(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newInvitePasskeyFixture(t, ctx)

	t.Run("ceremony expired", func(t *testing.T) {
		email, token, id := f.invite(t, ctx)
		a := virtualwebauthn.NewAuthenticator()
		sid, attestation := f.begin(t, token, &a, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2))
		if _, err := testPool.Exec(ctx, `UPDATE auth.webauthn_sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, sid); err != nil {
			t.Fatal(err)
		}
		if rr := f.finish(sid, attestation); errorCode(t, rr) != errs.CodeAuthSessionExpired {
			t.Errorf("finish after expiry: %d %s", rr.Code, rr.Body.String())
		}
		if usersWithEmail(t, ctx, email) != 0 || inviteStatus(t, ctx, id) != "pending" {
			t.Error("an expired ceremony created an account or used the invitation")
		}
	})

	t.Run("abandoned ceremony does not block starting again", func(t *testing.T) {
		email, token, id := f.invite(t, ctx)
		a1 := virtualwebauthn.NewAuthenticator()
		first, firstAttestation := f.begin(t, token, &a1, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2))
		a2 := virtualwebauthn.NewAuthenticator()
		second, attestation := f.begin(t, token, &a2, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2))
		if rr := f.finish(first, firstAttestation); rr.Code < 400 {
			t.Errorf("the replaced ceremony finished: %d", rr.Code)
		}
		if rr := f.finish(second, attestation); rr.Code != http.StatusOK {
			t.Fatalf("finish the new ceremony: %d %s", rr.Code, rr.Body.String())
		}
		if usersWithEmail(t, ctx, email) != 1 || inviteStatus(t, ctx, id) != "accepted" {
			t.Error("starting again did not accept the invitation once")
		}
	})

	t.Run("invitation revoked during the ceremony", func(t *testing.T) {
		email, token, id := f.invite(t, ctx)
		a := virtualwebauthn.NewAuthenticator()
		sid, attestation := f.begin(t, token, &a, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2))
		if err := f.invites.Revoke(ctx, f.tenantID, id); err != nil {
			t.Fatal(err)
		}
		if rr := f.finish(sid, attestation); errorCode(t, rr) != errs.CodeInviteInvalid {
			t.Errorf("finish after revocation: %d %s", rr.Code, rr.Body.String())
		}
		if usersWithEmail(t, ctx, email) != 0 {
			t.Error("an account was created for a revoked invitation")
		}
	})

	t.Run("revoked or expired invitation", func(t *testing.T) {
		_, revoked, id := f.invite(t, ctx)
		if err := f.invites.Revoke(ctx, f.tenantID, id); err != nil {
			t.Fatal(err)
		}
		if rr := f.post("/v1/invites/accept/passkey/begin", map[string]string{"token": revoked}); errorCode(t, rr) != errs.CodeInviteInvalid {
			t.Errorf("begin on a revoked invitation: %d %s", rr.Code, rr.Body.String())
		}
		_, expired, id := f.invite(t, ctx)
		if _, err := testPool.Exec(ctx, `UPDATE tenant.invites SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/v1/invites/lookup", "/v1/invites/accept/passkey/begin"} {
			if rr := f.post(path, map[string]string{"token": expired}); errorCode(t, rr) != errs.CodeInviteExpired {
				t.Errorf("%s on an expired invitation: %d %s", path, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("organisation has passkeys switched off", func(t *testing.T) {
		g := newInvitePasskeyFixture(t, ctx)
		setSignInMethods(t, ctx, g.tenantID, true, false, false, 15)
		_, token, _ := g.invite(t, ctx)
		rr := g.post("/v1/invites/lookup", map[string]string{"token": token})
		var preview invite.InvitationPreview
		_ = json.Unmarshal(rr.Body.Bytes(), &preview)
		if rr.Code != http.StatusOK || preview.Methods.Passkey || !preview.Methods.Password {
			t.Errorf("lookup with passkeys off: %d %s, want the password only", rr.Code, rr.Body.String())
		}
		if rr := g.post("/v1/invites/accept/passkey/begin", map[string]string{"token": token}); errorCode(t, rr) != errs.CodePasskeyDisabled {
			t.Errorf("begin with passkeys off: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("address already has an account", func(t *testing.T) {
		email, token, _ := f.invite(t, ctx)
		createTenantUser(t, ctx, createTenant(t, ctx, uniqueSlug("elsewhere")), email)
		rr := f.post("/v1/invites/lookup", map[string]string{"token": token})
		var preview invite.InvitationPreview
		_ = json.Unmarshal(rr.Body.Bytes(), &preview)
		if !preview.AccountExists {
			t.Errorf("lookup does not report the existing account: %s", rr.Body.String())
		}
		if rr := f.post("/v1/invites/accept/passkey/begin", map[string]string{"token": token}); errorCode(t, rr) != errs.CodeInviteAccountExists {
			t.Errorf("begin for an address with an account: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("ordinary sign-up cannot finish an invitation ceremony", func(t *testing.T) {
		email, token, id := f.invite(t, ctx)
		a := virtualwebauthn.NewAuthenticator()
		sid, attestation := f.begin(t, token, &a, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2))
		if _, _, err := f.passkeys.FinishTenantSignup(ctx, sid, attestation, "", "203.0.113.7", "test"); !errors.Is(err, errs.ErrPasskeySessionInvalid) {
			t.Errorf("hosted sign-up finished an invitation ceremony: %v", err)
		}
		if usersWithEmail(t, ctx, email) != 0 || inviteStatus(t, ctx, id) != "pending" {
			t.Error("an account was created without accepting the invitation")
		}
	})
}
