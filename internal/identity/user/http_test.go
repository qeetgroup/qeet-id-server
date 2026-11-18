package user

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestCheckNeedsTheMailerAndSignIns checks that the user handler is refused at
// start without the mailer that tells people of credential changes, what ends
// every way they are signed in, or what announces the sessions that ends.
func TestCheckNeedsTheMailerAndSignIns(t *testing.T) {
	full := Handler{Mailer: stubMailer{}, SignIns: stubSignIns{}, Signals: sessionsignal.New(nil)}
	for name, drop := range map[string]func(*Handler){
		"Mailer":  func(h *Handler) { h.Mailer = nil },
		"SignIns": func(h *Handler) { h.SignIns = nil },
		"Signals": func(h *Handler) { h.Signals = nil },
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

type (
	stubMailer  struct{ notifier.Sender }
	stubSignIns struct{ signInEnder }
)
