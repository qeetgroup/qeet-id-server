package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Domain-verification (internal/identity/domainverify) code→status mappings.
// Registered from an init() so this bounded context owns its own transport
// mappings without editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeDomainVerifyInvalidDomain:    http.StatusUnprocessableEntity,
		errs.CodeDomainVerifyExists:           http.StatusConflict,
		errs.CodeDomainVerifyDNSRecordMissing: http.StatusUnprocessableEntity,
		errs.CodeDomainVerifyClaimedByOther:   http.StatusConflict,
		errs.CodeDomainVerifyNotFound:         http.StatusNotFound,
	})
}
