package errs

// Organization error codes.
const (
	CodeOrgSlugTaken                     = "tenant.slug_taken"
	CodeOrganizationLastOwner            = "tenant.last_owner"
	CodeOrganizationOwnerOnly            = "tenant.owner_only"
	CodeOrganizationSelfSuspend          = "tenant.self_suspend"
	CodeOrganizationDeletionScheduled    = "tenant.deletion_scheduled"
	CodeOrganizationDeletionNotScheduled = "tenant.deletion_not_scheduled"
	CodeOrganizationRegionReadOnly       = "tenant.region_read_only"
	CodeOrganizationRegionUnavailable    = "tenant.region_unavailable"
)

var (
	ErrOrgSlugTaken                     = New(CodeOrgSlugTaken, "That organization URL is already taken. Choose another one.")
	ErrOrganizationLastOwner            = New(CodeOrganizationLastOwner, "This is the organization's last owner. Make someone else an owner first.")
	ErrOrganizationOwnerOnly            = New(CodeOrganizationOwnerOnly, "Only an owner of the organization can delete it or change its status.")
	ErrOrganizationSelfSuspend          = New(CodeOrganizationSelfSuspend, "An organization can't suspend itself: that would lock out every member, its owners too. Delete it instead.")
	ErrOrganizationDeletionScheduled    = New(CodeOrganizationDeletionScheduled, "This organization's deletion is already scheduled.")
	ErrOrganizationDeletionNotScheduled = New(CodeOrganizationDeletionNotScheduled, "This organization has no deletion scheduled.")
	ErrOrganizationRegionReadOnly       = New(CodeOrganizationRegionReadOnly, "An organization's region is where this service is hosted, so it can't be changed.")
	ErrOrganizationRegionUnavailable    = New(CodeOrganizationRegionUnavailable, "Organizations can only be created in the region this service is hosted in.")
)
