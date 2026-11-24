package oidc

import (
	"testing"
)

func TestDownscope(t *testing.T) {
	subject := []string{"openid", "profile", "email"}

	// No requested scope → keep the subject's scopes.
	if got, ok := downscope(subject, ""); !ok || len(got) != 3 {
		t.Errorf("empty request should keep subject scopes, got %v ok=%v", got, ok)
	}
	// A strict subset is granted.
	if got, ok := downscope(subject, "openid email"); !ok || len(got) != 2 {
		t.Errorf("subset should be granted, got %v ok=%v", got, ok)
	}
	// Requesting a scope the subject lacks is rejected (no escalation).
	if _, ok := downscope(subject, "openid admin"); ok {
		t.Error("must reject a scope the subject token doesn't hold")
	}
	if _, ok := downscope(subject, "admin"); ok {
		t.Error("must reject escalation to a brand-new scope")
	}
}
