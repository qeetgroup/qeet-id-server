package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Additional verification (internal/identity/verification) code→status mappings
// for the start-flow preconditions. Registered from an init() so this bounded
// context owns its own transport mappings without editing the shared
// error_status.go (whose base map already covers the code_* verification codes).
func init() {
	registerStatuses(map[string]int{
		errs.CodeVerifyUserNotFound: http.StatusNotFound,
		errs.CodeVerifyNoEmail:      http.StatusUnprocessableEntity,
		errs.CodeVerifyNoPhone:      http.StatusUnprocessableEntity,
	})
}
