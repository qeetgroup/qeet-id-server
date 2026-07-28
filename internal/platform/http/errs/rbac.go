package errs

// RBAC (role-based access control) error codes — stable, namespaced machine
// identifiers for role management, permission grants, and the Check hot path.
// Clients branch and localize on these, never on the message text. Once
// shipped, a code MUST NOT change.
const (
	CodeRBACRoleNameExists      = "rbac.role_name_exists"
	CodeRBACGroupOrRoleNotFound = "rbac.group_or_role_not_found"
	CodeRBACPermissionDenied    = "rbac.permission_denied"
	CodeRBACPermissionRequired  = "rbac.permission_required"
)

// RBAC errors. The Message is what the end user (or admin managing roles) sees.
var (
	ErrRBACRoleNameExists      = New(CodeRBACRoleNameExists, "A role with that name already exists.")
	ErrRBACGroupOrRoleNotFound = New(CodeRBACGroupOrRoleNotFound, "That group or role doesn't exist in this tenant.")
	ErrRBACPermissionDenied    = New(CodeRBACPermissionDenied, "You don't have permission to do that.")
	ErrRBACPermissionRequired  = New(CodeRBACPermissionRequired, "Specify the permission to check.")
)
