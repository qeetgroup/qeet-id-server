package errs

// Organization / tenant error codes.
const (
	CodeOrgSlugTaken    = "tenant.slug_taken"
	CodeTenantLastOwner = "tenant.last_owner"
)

var (
	ErrOrgSlugTaken = New(CodeOrgSlugTaken, "That organization URL is already taken. Choose another one.")
	// ErrTenantLastOwner: the change would leave the organisation with no
	// active owner, which nobody could then administer.
	ErrTenantLastOwner = New(CodeTenantLastOwner, "This is the organization's last owner. Make someone else an owner first.")
)
