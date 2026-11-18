package errs

// RBAC (role-based access control) error codes.
const (
	CodeRBACGrantExceedsCaller  = "rbac.grant_exceeds_caller"
	CodeRBACOwnerOnly           = "rbac.owner_only"
	CodeRBACTargetIsOwner       = "rbac.target_is_owner"
	CodeRBACTargetOutranks      = "rbac.target_outranks_caller"
	CodeRBACTrustChangeOutranks = "rbac.trust_change_outranks_caller"
)

// RBAC errors. ErrRBACUserOrRoleNotFound gives the same answer for missing and
// other-organization IDs, ErrRBACGrantExceedsCaller and ErrRBACTargetOutranks name
// the permission in their metadata.
var (
	ErrRBACUserOrRoleNotFound = New("rbac.user_or_role_not_found", KindNotFound, "That user or role doesn't exist in this organization.")
	ErrRBACPermissionDenied   = New("rbac.permission_denied", KindForbidden, "You don't have permission to do that.")
	ErrRBACGrantExceedsCaller = New(CodeRBACGrantExceedsCaller, KindForbidden, "You can't give a permission you don't have yourself.")
	ErrRBACOwnerOnly          = New(CodeRBACOwnerOnly, KindForbidden, "Only an owner can make someone an owner.")
	ErrRBACTargetIsOwner      = New(CodeRBACTargetIsOwner, KindForbidden, "Only an owner can change an owner's account or roles.")
	ErrRBACTargetOutranks     = New(CodeRBACTargetOutranks, KindForbidden, "You can't change the account of someone who holds a permission you don't.")
	// ErrRBACTrustChangeOutranks refuses changing what a connection trusts while
	// it signs in someone who outranks the caller: it could then sign in as them.
	ErrRBACTrustChangeOutranks = New(CodeRBACTrustChangeOutranks, KindForbidden, "This connection signs in someone who outranks you, so you can't change what it trusts. Ask an owner.")
)
