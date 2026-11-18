package auth

import (
	"net/http"
	"testing"
)

// TestCheckNeedsTheThrottleAndBotScorer checks that the sign-in handler is
// refused at start without the throttle on password changes or the bot
// scorer, rather than serving without them.
func TestCheckNeedsTheThrottleAndBotScorer(t *testing.T) {
	full := Handler{Throttle: func(h http.Handler) http.Handler { return h }, Bot: stubBot{}}
	for name, drop := range map[string]func(*Handler){
		"Throttle": func(h *Handler) { h.Throttle = nil },
		"Bot":      func(h *Handler) { h.Bot = nil },
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

type stubBot struct{ BotEvaluator }
