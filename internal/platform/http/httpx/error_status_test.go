package httpx

import (
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestEveryKindHasItsOwnStatus checks that each kind of error is answered with
// a status of its own, and that an error of no kind is a client error.
func TestEveryKindHasItsOwnStatus(t *testing.T) {
	seen := map[int]errs.Kind{}
	for k := errs.KindInvalid; k <= errs.KindUnavailable; k++ {
		s, ok := statusByKind[k]
		if !ok {
			t.Errorf("kind %d has no status", k)
			continue
		}
		if other, dup := seen[s]; dup {
			t.Errorf("kinds %d and %d are both answered %d", other, k, s)
		}
		seen[s] = k
	}
	if got := ErrorStatus(&errs.Error{Code: "x"}); got != http.StatusBadRequest {
		t.Errorf("an error of no kind is answered %d, want 400", got)
	}
	if got := StatusForCode("httpx_test.never_declared"); got != http.StatusBadRequest {
		t.Errorf("an unknown code is answered %d, want 400", got)
	}
}
