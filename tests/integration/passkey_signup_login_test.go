//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

// allowSelfRegistration is a registration policy that lets anyone sign up in
// any tenant, so the hosted (tenant) passkey signup path can run.
type allowSelfRegistration struct{}

func (allowSelfRegistration) SelfRegistrationEnabled(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func (allowSelfRegistration) ValidateForTenant(context.Context, uuid.UUID, string) error {
	return nil
}

// TestPasskeySignupThenLogin signs up with a passkey and signs straight back in
// with it the way a browser does: the authenticator returns the user handle the
// passkey was registered with. The signup ceremony registers the passkey under
// a WebAuthn user ID before any user row exists, so the account must be created
// with that same ID — otherwise the handle points at no user and the passkey
// never signs in again. Covers both signup paths (console: no tenant; hosted
// login: in a tenant) and both login styles (discoverable: no email, which
// both UIs use; email-first, where go-webauthn checks the handle).
func TestPasskeySignupThenLogin(t *testing.T) {
	requireDB(t)
	for _, signup := range []string{"console", "hosted"} {
		for _, login := range []string{"discoverable", "email-first"} {
			t.Run(signup+"/"+login, func(t *testing.T) {
				passkeySignupThenLogin(t, signup == "hosted", login == "discoverable")
			})
		}
	}
}

func passkeySignupThenLogin(t *testing.T, inTenant, discoverable bool) {
	ctx := context.Background()
	authSvc, _ := newAuth()
	authSvc.SetRegistrationPolicy(allowSelfRegistration{})
	svc := newPasskeySvcWithAuth(t, authSvc)

	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	email := uniqueSlug("pkhandle") + "@example.com"

	// Signup ceremony.
	var (
		sid      uuid.UUID
		creation *protocol.CredentialCreation
		err      error
	)
	if inTenant {
		tenantID := createTenant(t, ctx, uniqueSlug("pkhandle"))
		sid, creation, err = svc.BeginTenantSignup(ctx, tenantID, email, "Ada Lovelace")
	} else {
		sid, creation, err = svc.BeginSignup(ctx, email, "Ada Lovelace")
	}
	if err != nil {
		t.Fatalf("begin signup: %v", err)
	}
	optionsJSON, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("marshal creation options: %v", err)
	}
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	// A real authenticator keeps the WebAuthn user ID it was registered with
	// and returns it as the user handle on every sign-in.
	authenticator.Options.UserHandle = []byte(attestationOptions.UserID)
	attestation := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

	var userID uuid.UUID
	if inTenant {
		userID, _, err = svc.FinishTenantSignup(ctx, sid, json.RawMessage(attestation), "", "203.0.113.7", "test-agent")
	} else {
		_, userID, err = svc.FinishSignup(ctx, sid, json.RawMessage(attestation), "", "203.0.113.7", "test-agent")
	}
	if err != nil {
		t.Fatalf("finish signup: %v", err)
	}
	if userID == uuid.Nil {
		t.Fatal("signup should create a real user")
	}
	authenticator.AddCredential(cred)

	// Login ceremony with the passkey just registered.
	loginEmail := email
	if discoverable {
		loginEmail = ""
	}
	loginSID, assertion, err := svc.BeginLogin(ctx, loginEmail)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	assertJSON, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion options: %v", err)
	}
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(assertJSON))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	response := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)

	pair, err := svc.FinishLogin(ctx, loginSID, json.RawMessage(response), "203.0.113.7", "test-agent")
	if err != nil {
		t.Fatalf("finish login with the signup passkey: %v", err)
	}
	if pair.UserID != userID {
		t.Fatalf("login issued a session for user %v, want the signed-up user %v", pair.UserID, userID)
	}
}
