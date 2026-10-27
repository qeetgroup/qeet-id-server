package errs

// Organization / tenant error codes.
const (
	CodeOrgSlugTaken               = "tenant.slug_taken"
	CodeTenantLastOwner            = "tenant.last_owner"
	CodeTenantOwnerOnly            = "tenant.owner_only"
	CodeTenantSelfSuspend          = "tenant.self_suspend"
	CodeTenantDeletionScheduled    = "tenant.deletion_scheduled"
	CodeTenantDeletionNotScheduled = "tenant.deletion_not_scheduled"
)

var (
	ErrOrgSlugTaken               = New(CodeOrgSlugTaken, "That organization URL is already taken. Choose another one.")
	ErrTenantLastOwner            = New(CodeTenantLastOwner, "This is the organization's last owner. Make someone else an owner first.")
	ErrTenantOwnerOnly            = New(CodeTenantOwnerOnly, "Only an owner of the organization can delete it or change its status.")
	ErrTenantSelfSuspend          = New(CodeTenantSelfSuspend, "An organization can't suspend itself: that would lock out every member, its owners too. Delete it instead.")
	ErrTenantDeletionScheduled    = New(CodeTenantDeletionScheduled, "This organization's deletion is already scheduled.")
	ErrTenantDeletionNotScheduled = New(CodeTenantDeletionNotScheduled, "This organization has no deletion scheduled.")
)
