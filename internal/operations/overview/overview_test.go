package overview

import "testing"

// TestNewServiceRefusesMissingDependencies checks that the service is never
// built without its authorizer or its sign-in settings.
func TestNewServiceRefusesMissingDependencies(t *testing.T) {
	if _, err := NewService(nil, nil, signInSettings{}); err == nil {
		t.Error("no authorizer: built, want refused")
	}
	if _, err := NewService(nil, allowOnly(), nil); err == nil {
		t.Error("no sign-in settings: built, want refused")
	}
}
