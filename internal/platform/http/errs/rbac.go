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
	CodeRBACTrustChangeOutranks = "rbac.trust_change_outranks_caller"
	CodeRBACSystemRoleFixed     = "rbac.system_role_fixed"
	CodeRBACRoleInUse           = "rbac.role_in_use"
)

// RBAC errors. ErrRBACUserOrRoleNotFound gives the same answer for missing and
// other-organization IDs, ErrRBACGrantExceedsCaller and ErrRBACTargetOutranks name
// the permission in their metadata, and ErrRBACRoleInUse counts the holders.
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
	// ErrRBACTrustChangeOutranks refuses changing what a connection trusts while
	// it signs in someone who outranks the caller: it could then sign in as them.
	ErrRBACTrustChangeOutranks = New(CodeRBACTrustChangeOutranks,
		"This connection signs in someone who outranks you, so you can't change what it trusts. Ask an owner.")
	ErrRBACSystemRoleFixed = New(CodeRBACSystemRoleFixed, "A built-in role can't be changed. Create a role of your own for a different set of permissions.")
	ErrRBACRoleInUse       = New(CodeRBACRoleInUse, "Someone still holds this role. Give its people, groups and invitations another role first.")
)
