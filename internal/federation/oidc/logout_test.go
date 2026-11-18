package oidc

import (
	"testing"

	"github.com/google/uuid"
)

// TestLogoutTicketsVerify checks that the sign-out tickets this server signs
// verify for what they name, and only for it.
func TestLogoutTicketsVerify(t *testing.T) {
	svc := NewService(nil, testIssuer(t))
	session := uuid.New()
	confirm, err := svc.logoutConfirmation(session)
	if err != nil {
		t.Fatalf("confirmation: %v", err)
	}
	if !svc.confirmedFor(confirm, session) {
		t.Error("a confirmation ticket did not confirm its own session")
	}
	if svc.confirmedFor(confirm, uuid.New()) {
		t.Error("a confirmation ticket confirmed another session")
	}
	next, err := svc.logoutContinuation("https://app.example.test/signed-out")
	if err != nil {
		t.Fatalf("continuation: %v", err)
	}
	if target, ok := svc.continuationTarget(next); !ok || target != "https://app.example.test/signed-out" {
		t.Errorf("continuation target = %q, %t", target, ok)
	}
	if _, ok := svc.continuationTarget(confirm); ok {
		t.Error("a confirmation ticket was taken as a continuation")
	}
}
