package errs

// RBAC (role-based access control) error codes.
const (
	CodeRBACRoleNameExists      = "rbac.role_name_exists"
	CodeRBACGroupOrRoleNotFound = "rbac.group_or_role_not_found"
	CodeRBACUserOrRoleNotFound  = "rbac.user_or_role_not_found"
	CodeRBACPermissionDenied    = "rbac.permission_denied"
	CodeRBACPermissionRequired  = "rbac.permission_required"
	CodeRBACGrantExceedsCaller  = "rbac.grant_exceeds_caller"
	CodeRBACOwnerOnly           = "rbac.owner_only"
)

// RBAC errors. ErrRBACUserOrRoleNotFound gives the same answer for missing and
// other-tenant IDs, and ErrRBACGrantExceedsCaller names the permission in its
// metadata.
var (
	ErrRBACRoleNameExists      = New(CodeRBACRoleNameExists, "A role with that name already exists.")
	ErrRBACGroupOrRoleNotFound = New(CodeRBACGroupOrRoleNotFound, "That group or role doesn't exist in this tenant.")
	ErrRBACUserOrRoleNotFound  = New(CodeRBACUserOrRoleNotFound, "That user or role doesn't exist in this tenant.")
	ErrRBACPermissionDenied    = New(CodeRBACPermissionDenied, "You don't have permission to do that.")
	ErrRBACPermissionRequired  = New(CodeRBACPermissionRequired, "Specify the permission to check.")
	ErrRBACGrantExceedsCaller  = New(CodeRBACGrantExceedsCaller, "You can't give a permission you don't have yourself.")
	ErrRBACOwnerOnly           = New(CodeRBACOwnerOnly, "Only an owner can make someone an owner.")
)
