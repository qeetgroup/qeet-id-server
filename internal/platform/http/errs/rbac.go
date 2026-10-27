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
	CodeRBACTargetIsOwner       = "rbac.target_is_owner"
	CodeRBACTargetOutranks      = "rbac.target_outranks_caller"
	CodeRBACSystemRoleFixed     = "rbac.system_role_fixed"
)

// RBAC errors. ErrRBACUserOrRoleNotFound gives the same answer for missing and
// other-tenant IDs, and ErrRBACGrantExceedsCaller and ErrRBACTargetOutranks
// name the permission in their metadata.
var (
	ErrRBACRoleNameExists      = New(CodeRBACRoleNameExists, "A role with that name already exists.")
	ErrRBACGroupOrRoleNotFound = New(CodeRBACGroupOrRoleNotFound, "That group or role doesn't exist in this tenant.")
	ErrRBACUserOrRoleNotFound  = New(CodeRBACUserOrRoleNotFound, "That user or role doesn't exist in this tenant.")
	ErrRBACPermissionDenied    = New(CodeRBACPermissionDenied, "You don't have permission to do that.")
	ErrRBACPermissionRequired  = New(CodeRBACPermissionRequired, "Specify the permission to check.")
	ErrRBACGrantExceedsCaller  = New(CodeRBACGrantExceedsCaller, "You can't give a permission you don't have yourself.")
	ErrRBACOwnerOnly           = New(CodeRBACOwnerOnly, "Only an owner can make someone an owner.")
	ErrRBACTargetIsOwner       = New(CodeRBACTargetIsOwner, "Only an owner can change an owner's account or roles.")
	ErrRBACTargetOutranks      = New(CodeRBACTargetOutranks, "You can't change the account of someone who holds a permission you don't.")
	ErrRBACSystemRoleFixed     = New(CodeRBACSystemRoleFixed, "The owner role always holds every permission; it can't be changed.")
)
