package organization

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeOwnerOnly            = "organization.owner_only"
	CodeSelfSuspend          = "organization.self_suspend"
	CodeDeletionScheduled    = "organization.deletion_scheduled"
	CodeDeletionNotScheduled = "organization.deletion_not_scheduled"
	CodeRegionReadOnly       = "organization.region_read_only"
	CodeRegionUnavailable    = "organization.region_unavailable"
	// Gate for actions that require a verified email (e.g. creating an org).
	CodeEmailNotVerified = "verification.email_not_verified"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrOwnerOnly            = errs.New(CodeOwnerOnly, errs.KindForbidden, "Only an owner of the organization can delete it or change its status.")
	ErrSelfSuspend          = errs.New(CodeSelfSuspend, errs.KindForbidden, "An organization can't suspend itself: that would lock out every member, its owners too. Delete it instead.")
	ErrDeletionScheduled    = errs.New(CodeDeletionScheduled, errs.KindConflict, "This organization's deletion is already scheduled.")
	ErrDeletionNotScheduled = errs.New(CodeDeletionNotScheduled, errs.KindConflict, "This organization has no deletion scheduled.")
	ErrRegionReadOnly       = errs.New(CodeRegionReadOnly, errs.KindUnprocessable, "An organization's region is where this service is hosted, so it can't be changed.")
	ErrRegionUnavailable    = errs.New(CodeRegionUnavailable, errs.KindUnprocessable, "Organizations can only be created in the region this service is hosted in.")
	ErrEmailNotVerified     = errs.New(CodeEmailNotVerified, errs.KindForbidden, "Verify your email address before creating an organization.")
)
