package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// statusByCode maps each error code to its HTTP status. It lives in the
// transport layer, not on errs.Error, so the errs catalog stays
// transport-agnostic. Keep it in sync with that catalog.
var statusByCode = map[string]int{
	// Generic platform errors.
	errs.CodeBadRequest:          http.StatusBadRequest,
	errs.CodeUnauthorized:        http.StatusUnauthorized,
	errs.CodeForbidden:           http.StatusForbidden,
	errs.CodeStepUpRequired:      http.StatusForbidden,
	errs.CodeNotFound:            http.StatusNotFound,
	errs.CodeConflict:            http.StatusConflict,
	errs.CodeUnprocessable:       http.StatusUnprocessableEntity,
	errs.CodeValidation:          http.StatusUnprocessableEntity,
	errs.CodeTooManyRequests:     http.StatusTooManyRequests,
	errs.CodeRequestBodyTooLarge: http.StatusRequestEntityTooLarge,
	errs.CodeUnsupportedMedia:    http.StatusUnsupportedMediaType,
	errs.CodeInternal:            http.StatusInternalServerError,
	errs.CodeNotImplemented:      http.StatusNotImplemented,

	// MFA.
	errs.CodeMFATOTPCodeInvalid:     http.StatusBadRequest,
	errs.CodeMFAOTPCodeInvalid:      http.StatusBadRequest,
	errs.CodeMFACodeInvalid:         http.StatusUnauthorized,
	errs.CodeMFAEnrollNotStarted:    http.StatusBadRequest,
	errs.CodeMFANotConfirmed:        http.StatusBadRequest,
	errs.CodeMFAChannelInvalid:      http.StatusUnprocessableEntity,
	errs.CodeMFADestinationRequired: http.StatusUnprocessableEntity,
	errs.CodeMFAWebAuthnUnavailable: http.StatusNotImplemented,

	// Auth / credentials.
	errs.CodeAuthSessionInvalid:   http.StatusBadRequest,
	errs.CodeAuthAccountInactive:  http.StatusForbidden,
	errs.CodeAuthEmailExists:      http.StatusConflict,
	errs.CodeAuthEmailRequired:    http.StatusUnprocessableEntity,
	errs.CodeAuthSessionExpired:   http.StatusBadRequest,
	errs.CodeAuthPasswordBreached: http.StatusUnprocessableEntity,

	// Recovery.
	errs.CodeResetLinkInvalid:    http.StatusBadRequest,
	errs.CodeMagicLinkInvalid:    http.StatusBadRequest,
	errs.CodeRecoveryLinkUsed:    http.StatusBadRequest,
	errs.CodeRecoveryLinkExpired: http.StatusBadRequest,

	// Verification.
	errs.CodeVerifyCodeInvalid: http.StatusBadRequest,
	errs.CodeVerifyCodeUsed:    http.StatusBadRequest,
	errs.CodeVerifyCodeExpired: http.StatusBadRequest,
	errs.CodeEmailNotVerified:  http.StatusForbidden,
	errs.CodeEmailTaken:        http.StatusConflict,

	// Invitations.
	errs.CodeInviteLinkInvalid:      http.StatusBadRequest,
	errs.CodeInviteInvalid:          http.StatusBadRequest,
	errs.CodeInviteExpired:          http.StatusBadRequest,
	errs.CodeInviteAccountExists:    http.StatusConflict,
	errs.CodeInviteEmailMismatch:    http.StatusForbidden,
	errs.CodeInviteEmailNotVerified: http.StatusForbidden,

	// Passkeys.
	errs.CodePasskeyExists:      http.StatusConflict,
	errs.CodePasskeyLoginFailed: http.StatusUnauthorized,

	// Organization / tenant.
	errs.CodeOrgSlugTaken:    http.StatusConflict,
	errs.CodeTenantLastOwner: http.StatusConflict,
}

// registerStatuses adds a domain's code→status entries to statusByCode; each
// error_status_<domain>.go calls it from init.
func registerStatuses(m map[string]int) {
	for k, v := range m {
		statusByCode[k] = v
	}
}

// statusForCode returns the HTTP status for a canonical error code. An unmapped
// code falls back to 400 (client error) — a forgotten mapping should never
// surface to a user as a 500.
func statusForCode(code string) int {
	if s, ok := statusByCode[code]; ok {
		return s
	}
	return http.StatusBadRequest
}
