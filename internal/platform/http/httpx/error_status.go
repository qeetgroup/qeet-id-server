package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// statusByCode maps each canonical error code to its HTTP status. This lives in
// the transport layer (not on the domain error) so the errs catalog stays
// transport-agnostic — the same errors can back gRPC/CLI/jobs with a different
// mapping. Keep this in sync with the errs catalog.
var statusByCode = map[string]int{
	// Generic platform errors.
	errs.CodeBadRequest:      http.StatusBadRequest,
	errs.CodeUnauthorized:    http.StatusUnauthorized,
	errs.CodeForbidden:       http.StatusForbidden,
	errs.CodeStepUpRequired:  http.StatusForbidden,
	errs.CodeNotFound:        http.StatusNotFound,
	errs.CodeConflict:        http.StatusConflict,
	errs.CodeUnprocessable:   http.StatusUnprocessableEntity,
	errs.CodeValidation:      http.StatusUnprocessableEntity,
	errs.CodeTooManyRequests: http.StatusTooManyRequests,
	errs.CodeInternal:        http.StatusInternalServerError,
	errs.CodeNotImplemented:  http.StatusNotImplemented,

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

	// Invitations.
	errs.CodeInviteLinkInvalid: http.StatusBadRequest,
	errs.CodeInviteInvalid:     http.StatusBadRequest,
	errs.CodeInviteExpired:     http.StatusBadRequest,

	// Passkeys.
	errs.CodePasskeyExists:      http.StatusConflict,
	errs.CodePasskeyLoginFailed: http.StatusUnauthorized,

	// Organization / tenant.
	errs.CodeOrgSlugTaken: http.StatusConflict,

	// Copilot.
	"copilot_unconfigured": http.StatusConflict,
}

// registerStatuses merges a domain's code→status entries into statusByCode.
// Per-domain files (error_status_<domain>.go) call this from an init() so each
// bounded context owns its own mappings without editing this shared file.
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
