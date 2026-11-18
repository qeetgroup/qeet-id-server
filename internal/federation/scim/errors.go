package scim

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrTokenIDInvalid      = errs.New("scim.token_id_invalid", errs.KindInvalid, "That SCIM token identifier isn't valid.")
	ErrTokenNotFound       = errs.New("scim.token_not_found", errs.KindNotFound, "That SCIM token doesn't exist or is already revoked.")
	ErrTokenNameInvalid    = errs.New("scim.token_name_invalid", errs.KindUnprocessable, "Enter a name for the SCIM token, up to 200 characters.")
	ErrTokenExpiryInvalid  = errs.New("scim.token_expiry_invalid", errs.KindUnprocessable, "A SCIM token's expiry must be in the future.")
	ErrTokenOverlapInvalid = errs.New("scim.token_overlap_invalid", errs.KindUnprocessable, "The overlap must be between 0 and 720 hours.")
	ErrTokenInactive       = errs.New("scim.token_inactive", errs.KindConflict, "That SCIM token is revoked, expired or already rotated, so it can't be rotated.")
	ErrTokenLimit          = errs.New("scim.token_limit", errs.KindConflict, "This organization has as many SCIM tokens as it can hold. Revoke one first.")
)
