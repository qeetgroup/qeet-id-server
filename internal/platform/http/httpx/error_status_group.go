package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Group (internal/identity/groups) code→status mappings. Registered from an
// init() so this bounded context owns its own transport mappings without
// editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeGroupNotFound: http.StatusNotFound,
	})
}
