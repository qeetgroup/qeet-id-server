package errs

// LDAP / Active Directory federation error codes — stable, namespaced machine
// identifiers for directory connection management and the username/password bind
// authentication flow. Clients branch and localize on these, never on the
// message text. Once shipped, a code MUST NOT change.
const (
	CodeLDAPDialFailed               = "ldap.dial_failed"
	CodeLDAPServiceBindFailed        = "ldap.service_bind_failed"
	CodeLDAPCredentialsRequired      = "ldap.credentials_required"
	CodeLDAPDirectoryUnreachable     = "ldap.directory_unreachable"
	CodeLDAPInvalidCredentials       = "ldap.invalid_credentials"
	CodeLDAPEmailAttributeMissing    = "ldap.email_attribute_missing"
	CodeLDAPConnectionDisabled       = "ldap.connection_disabled"
	CodeLDAPConnectionFieldsRequired = "ldap.connection_fields_required"
	CodeLDAPServerURLInvalid         = "ldap.server_url_invalid"
	CodeLDAPStatusInvalid            = "ldap.status_invalid"
)

// LDAP errors. The Message is what the end user (or admin configuring a
// connection) sees. Transient reachability failures are marked retryable.
var (
	ErrLDAPDialFailed               = New(CodeLDAPDialFailed, "We couldn't reach the directory server. Please try again.").AsRetryable()
	ErrLDAPServiceBindFailed        = New(CodeLDAPServiceBindFailed, "We couldn't connect to the directory with the configured service account.")
	ErrLDAPCredentialsRequired      = New(CodeLDAPCredentialsRequired, "Enter your username and password.")
	ErrLDAPDirectoryUnreachable     = New(CodeLDAPDirectoryUnreachable, "We couldn't reach the directory server. Please try again.").AsRetryable()
	ErrLDAPInvalidCredentials       = New(CodeLDAPInvalidCredentials, "That username or password is incorrect.")
	ErrLDAPEmailAttributeMissing    = New(CodeLDAPEmailAttributeMissing, "Your directory account doesn't have an email address, which is required.")
	ErrLDAPConnectionDisabled       = New(CodeLDAPConnectionDisabled, "This directory connection is disabled.")
	ErrLDAPConnectionFieldsRequired = New(CodeLDAPConnectionFieldsRequired, "Name, server URL, bind DN, bind password and base DN are required.")
	ErrLDAPServerURLInvalid         = New(CodeLDAPServerURLInvalid, "The server URL must start with ldap:// or ldaps://.")
	ErrLDAPStatusInvalid            = New(CodeLDAPStatusInvalid, "Status must be draft, active or disabled.")
)
