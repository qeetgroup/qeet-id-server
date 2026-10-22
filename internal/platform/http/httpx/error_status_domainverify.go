package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the domain-verification error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeDomainVerifyInvalidDomain:    http.StatusUnprocessableEntity,
		errs.CodeDomainVerifyExists:           http.StatusConflict,
		errs.CodeDomainVerifyDNSRecordMissing: http.StatusUnprocessableEntity,
		errs.CodeDomainVerifyClaimedByOther:   http.StatusConflict,
		errs.CodeDomainVerifyNotFound:         http.StatusNotFound,
	})
}
