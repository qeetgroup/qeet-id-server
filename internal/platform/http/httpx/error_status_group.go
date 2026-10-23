package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the group error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeGroupNotFound:            http.StatusNotFound,
		errs.CodeGroupUserNotFound:        http.StatusNotFound,
		errs.CodeGroupParentNotFound:      http.StatusNotFound,
		errs.CodeGroupCycle:               http.StatusBadRequest,
		errs.CodeGroupNameExists:          http.StatusConflict,
		errs.CodeGroupTemplateNameExists:  http.StatusConflict,
		errs.CodeGroupTemplateUnnamed:     http.StatusUnprocessableEntity,
		errs.CodeGroupTemplateNodeUnnamed: http.StatusUnprocessableEntity,
		errs.CodeGroupTemplateEmpty:       http.StatusUnprocessableEntity,
		errs.CodeGroupTemplateTooDeep:     http.StatusUnprocessableEntity,
		errs.CodeGroupTemplateTooLarge:    http.StatusUnprocessableEntity,
		errs.CodeGroupImportEmpty:         http.StatusUnprocessableEntity,
		errs.CodeGroupImportTooLarge:      http.StatusUnprocessableEntity,
	})
}
