package organization

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// TestCheckNeedsTheSignInServiceAndSignals checks that the organization
// handler is refused at start without what lets the creator enter a new
// organization or what announces the sessions a suspension or deletion ends.
func TestCheckNeedsTheSignInServiceAndSignals(t *testing.T) {
	full := Handler{AuthService: stubIssuer{}, Signals: sessionsignal.New(nil)}
	for name, drop := range map[string]func(*Handler){
		"AuthService": func(h *Handler) { h.AuthService = nil },
		"Signals":     func(h *Handler) { h.Signals = nil },
	} {
		h := full
		drop(&h)
		if err := h.Check(); err == nil {
			t.Errorf("Check without %s: nil; want an error", name)
		}
	}
	if err := full.Check(); err != nil {
		t.Errorf("Check with every dependency: %v", err)
	}
}

type stubIssuer struct{ tokenIssuer }
