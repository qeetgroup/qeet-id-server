package rbac

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeRoleNameExists  = "rbac.role_name_exists"
	CodeSystemRoleFixed = "rbac.system_role_fixed"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrAuthInsufficientScope = errs.New("auth.insufficient_scope", errs.KindForbidden, "This application wasn't given permission for this. Sign in to the application again and approve the access it asks for.")
	ErrRoleNameExists        = errs.New(CodeRoleNameExists, errs.KindConflict, "A role with that name already exists.")
	ErrGroupOrRoleNotFound   = errs.New("rbac.group_or_role_not_found", errs.KindNotFound, "That group or role doesn't exist in this organization.")
	ErrPermissionRequired    = errs.New("rbac.permission_required", errs.KindInvalid, "Specify the permission to check.")
	ErrSystemRoleFixed       = errs.New(CodeSystemRoleFixed, errs.KindForbidden, "A built-in role can't be changed. Create a role of your own for a different set of permissions.")
)
