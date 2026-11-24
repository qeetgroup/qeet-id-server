package vc

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeSubjectTypeRequired = "vc.subject_type_required"
	CodeUserNotMember       = "vc.user_not_member"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrSubjectTypeRequired = errs.New(CodeSubjectTypeRequired, errs.KindUnprocessable, "A credential subject and type are required.")
	ErrClaimsInvalid       = errs.New("vc.claims_invalid", errs.KindUnprocessable, "Credential claims must be a valid JSON object.")
	ErrCredentialRequired  = errs.New("vc.credential_required", errs.KindUnprocessable, "A credential (JWT) is required.")
	ErrUserNotMember       = errs.New(CodeUserNotMember, errs.KindUnprocessable, "That person isn't a member of this organization.")
	ErrCredentialNotFound  = errs.New("vc.credential_not_found", errs.KindNotFound, "We couldn't find that credential.")
)
