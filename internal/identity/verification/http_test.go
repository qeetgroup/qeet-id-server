package verification

import (
	"net/http"
	"testing"
)

// TestCheckNeedsTheThrottle checks that the verification handler is refused
// at start without the throttle on its code-sending routes.
func TestCheckNeedsTheThrottle(t *testing.T) {
	if err := (&Handler{}).Check(); err == nil {
		t.Error("Check without the throttle: nil; want an error")
	}
	if err := (&Handler{Throttle: func(h http.Handler) http.Handler { return h }}).Check(); err != nil {
		t.Errorf("Check with the throttle: %v", err)
	}
}
