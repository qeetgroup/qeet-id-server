package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the user error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeUserImportSourceInvalid: http.StatusBadRequest,
		errs.CodeUserImportFileTooLarge:  http.StatusUnprocessableEntity,
		errs.CodeUserImportEmpty:         http.StatusUnprocessableEntity,
		errs.CodeUserImportBatchTooLarge: http.StatusUnprocessableEntity,
		errs.CodeUserManagedElsewhere:    http.StatusForbidden,
		errs.CodeUserCredentialsShared:   http.StatusForbidden,
		errs.CodeUserManagedHere:         http.StatusConflict,
	})
}
