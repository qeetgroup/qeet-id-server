package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Passkey code→status mappings for the NEW passkey codes added in errs/passkey.go
// beyond the originals already mapped in the base error_status.go. Registered
// from init() so the passkey domain owns its own transport mappings. Each status
// matches the generic sentinel the specific error replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodePasskeyUserNotFound:       http.StatusNotFound,
		errs.CodePasskeySessionMismatch:    http.StatusBadRequest,
		errs.CodePasskeySessionInvalid:     http.StatusBadRequest,
		errs.CodePasskeyAttestationInvalid: http.StatusBadRequest,
		errs.CodePasskeyAssertionInvalid:   http.StatusBadRequest,
		errs.CodePasskeyNoCredentials:      http.StatusBadRequest,
		errs.CodePasskeyMFAFailed:          http.StatusUnauthorized,
		errs.CodePasskeyCeremonyFailed:     http.StatusBadRequest,
	})
}
