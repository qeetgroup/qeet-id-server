//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/google/uuid"
)

// The RP config a virtual authenticator must mirror. Matches the webauthn.New
// config newPasskeySvc (coverage_test.go) builds the service with.
const (
	pkRPID     = "localhost"
	pkRPName   = "Qeet ID"
	pkRPOrigin = "http://localhost:3000"
)

// TestPasskeyFullCeremony drives the entire begin→create→finish signup ceremony
// and begin→assert→finish login ceremony end-to-end against the real passkey
// service + go-webauthn verifier, using a virtual authenticator that produces
// genuine attestation/assertion signatures (QID-07: the first test to complete a
// real WebAuthn ceremony rather than stopping at challenge issuance).
func TestPasskeyFullCeremony(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newPasskeySvc(t)

	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	email := uniqueSlug("pkfull") + "@example.com"

	// Registration ceremony (tenant-less passkey-first signup)
	sid, creation, err := svc.BeginSignup(ctx, email, "Ada Lovelace")
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
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

	pair, userID, err := svc.FinishSignup(ctx, sid, json.RawMessage(attestationResponse), "My Laptop", "203.0.113.7", "test-agent")
	if err != nil {
		t.Fatalf("finish signup (attestation verification): %v", err)
	}
	if pair == nil || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("signup should issue a full token pair, got %+v", pair)
	}
	if userID == uuid.Nil {
		t.Fatal("signup should create a real user")
	}

	// The credential is now the account's founding credential — it must show up.
	creds, err := svc.List(ctx, userID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("want exactly 1 registered passkey after signup, got %d", len(creds))
	}

	// Register the credential with the virtual authenticator so it can now be
	// used to sign assertions for the login ceremony.
	authenticator.AddCredential(cred)

	// Authentication ceremony (log in with the passkey just registered)
	loginSID, assertion, err := svc.BeginLogin(ctx, email)
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
	if authenticator.FindAllowedCredential(*assertionOptions) == nil {
		t.Fatal("registered credential should be allowed by the login assertion options")
	}
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)

	loginPair, err := svc.FinishLogin(ctx, loginSID, json.RawMessage(assertionResponse), "203.0.113.7", "test-agent")
	if err != nil {
		t.Fatalf("finish login (assertion verification): %v", err)
	}
	if loginPair == nil || loginPair.AccessToken == "" || loginPair.RefreshToken == "" {
		t.Fatalf("login should issue a full token pair, got %+v", loginPair)
	}
	if loginPair.UserID != userID {
		t.Fatalf("login issued a session for user %v, want the signed-up user %v", loginPair.UserID, userID)
	}
}

// TestPasskeyLoginRejectsForgedAssertion proves the verifier isn't a rubber
// stamp: an assertion signed by a DIFFERENT authenticator/credential than the
// one registered must be rejected. Without this, a "passing" ceremony test
// could still hide a verifier that accepts any well-formed payload.
func TestPasskeyLoginRejectsForgedAssertion(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newPasskeySvc(t)

	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	realAuth := virtualwebauthn.NewAuthenticator()
	realCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	email := uniqueSlug("pkforge") + "@example.com"

	sid, creation, err := svc.BeginSignup(ctx, email, "Grace Hopper")
	if err != nil {
		t.Fatalf("begin signup: %v", err)
	}
	optionsJSON, _ := json.Marshal(creation)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, realAuth, realCred, *attestationOptions)
	if _, _, err := svc.FinishSignup(ctx, sid, json.RawMessage(attestationResponse), "", "203.0.113.7", "test-agent"); err != nil {
		t.Fatalf("finish signup: %v", err)
	}
	realAuth.AddCredential(realCred)

	// Begin a legitimate login, but answer it with an assertion from a rogue
	// authenticator holding a different key the server never registered.
	loginSID, assertion, err := svc.BeginLogin(ctx, email)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	assertJSON, _ := json.Marshal(assertion)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(assertJSON))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}
	rogueAuth := virtualwebauthn.NewAuthenticator()
	rogueCred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	// Force the rogue credential to claim the real credential's ID so it clears
	// the allow-list check but still signs with the wrong (rogue) private key.
	rogueCred.ID = realCred.ID
	rogueAuth.AddCredential(rogueCred)
	forged := virtualwebauthn.CreateAssertionResponse(rp, rogueAuth, rogueCred, *assertionOptions)

	if _, err := svc.FinishLogin(ctx, loginSID, json.RawMessage(forged), "203.0.113.7", "test-agent"); err == nil {
		t.Fatal("login must reject an assertion signed by a credential the server never registered")
	}
}
