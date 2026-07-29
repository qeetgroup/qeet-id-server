package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// User (internal/identity/users) code→status mappings. Registered from an
// init() so this bounded context owns its own transport mappings without
// editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeUserImportSourceInvalid: http.StatusBadRequest,
		errs.CodeUserImportFileTooLarge:  http.StatusUnprocessableEntity,
		errs.CodeUserImportEmpty:         http.StatusUnprocessableEntity,
		errs.CodeUserImportBatchTooLarge: http.StatusUnprocessableEntity,
	})
}
