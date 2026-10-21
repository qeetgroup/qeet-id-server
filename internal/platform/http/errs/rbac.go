package errs

// RBAC (role-based access control) error codes — stable, namespaced machine
// identifiers for role management, permission grants, and the Check hot path.
// Clients branch and localize on these, never on the message text. Once
// shipped, a code MUST NOT change.
const (
	CodeRBACRoleNameExists      = "rbac.role_name_exists"
	CodeRBACGroupOrRoleNotFound = "rbac.group_or_role_not_found"
	CodeRBACUserOrRoleNotFound  = "rbac.user_or_role_not_found"
	CodeRBACPermissionDenied    = "rbac.permission_denied"
	CodeRBACPermissionRequired  = "rbac.permission_required"
	CodeRBACGrantExceedsCaller  = "rbac.grant_exceeds_caller"
	CodeRBACOwnerOnly           = "rbac.owner_only"
)

// RBAC errors. The Message is what the end user (or admin managing roles) sees.
var (
	ErrRBACRoleNameExists      = New(CodeRBACRoleNameExists, "A role with that name already exists.")
	ErrRBACGroupOrRoleNotFound = New(CodeRBACGroupOrRoleNotFound, "That group or role doesn't exist in this tenant.")
	// ErrRBACUserOrRoleNotFound is the one answer to every refused role
	// assignment, whether an id is missing or belongs to another tenant, so the
	// response can't be used to probe for ids.
	ErrRBACUserOrRoleNotFound = New(CodeRBACUserOrRoleNotFound, "That user or role doesn't exist in this tenant.")
	ErrRBACPermissionDenied   = New(CodeRBACPermissionDenied, "You don't have permission to do that.")
	ErrRBACPermissionRequired = New(CodeRBACPermissionRequired, "Specify the permission to check.")
	// ErrRBACGrantExceedsCaller: the grant, role or invitation would give
	// someone a permission the caller doesn't hold here; its metadata names it.
	ErrRBACGrantExceedsCaller = New(CodeRBACGrantExceedsCaller, "You can't give a permission you don't have yourself.")
	// ErrRBACOwnerOnly: only an owner gives someone the owner role.
	ErrRBACOwnerOnly = New(CodeRBACOwnerOnly, "Only an owner can make someone an owner.")
)
