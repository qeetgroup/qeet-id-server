package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// statusByKind is the HTTP status each kind of error is answered with.
var statusByKind = map[errs.Kind]int{
	errs.KindInvalid:          http.StatusBadRequest,
	errs.KindUnauthenticated:  http.StatusUnauthorized,
	errs.KindPaymentRequired:  http.StatusPaymentRequired,
	errs.KindForbidden:        http.StatusForbidden,
	errs.KindNotFound:         http.StatusNotFound,
	errs.KindConflict:         http.StatusConflict,
	errs.KindGone:             http.StatusGone,
	errs.KindTooLarge:         http.StatusRequestEntityTooLarge,
	errs.KindUnsupportedMedia: http.StatusUnsupportedMediaType,
	errs.KindUnprocessable:    http.StatusUnprocessableEntity,
	errs.KindTooManyRequests:  http.StatusTooManyRequests,
	errs.KindInternal:         http.StatusInternalServerError,
	errs.KindNotImplemented:   http.StatusNotImplemented,
	errs.KindBadGateway:       http.StatusBadGateway,
	errs.KindUnavailable:      http.StatusServiceUnavailable,
}

// ErrorStatus is the HTTP status WriteError answers e with, for a handler that
// reports an error inside its response rather than as one. An error of no
// known kind is answered 400: a client error, never a 500 by accident.
func ErrorStatus(e *errs.Error) int {
	if s, ok := statusByKind[e.Kind]; ok {
		return s
	}
	return http.StatusBadRequest
}

// StatusForCode is the HTTP status WriteError answers the error declared with
// code with, for a handler that shows the error on a page of its own.
func StatusForCode(code string) int {
	if e, ok := errs.Lookup(code); ok {
		return ErrorStatus(e)
	}
	return http.StatusBadRequest
}
