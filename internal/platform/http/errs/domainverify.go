package errs

// Domain verification error codes: proving ownership of an email domain with a
// DNS TXT record.
const (
	CodeDomainVerifyInvalidDomain  = "domainverify.invalid_domain"
	CodeDomainVerifyClaimedByOther = "domainverify.claimed_by_other"
)

// Domain-verification errors. The Message is what the end user sees — edit
// wording here, in one place.
var (
	ErrDomainVerifyInvalidDomain  = New(CodeDomainVerifyInvalidDomain, KindUnprocessable, "Enter a valid domain, e.g. acme.com.")
	ErrDomainVerifyClaimedByOther = New(CodeDomainVerifyClaimedByOther, KindConflict, "This domain is already verified by another organization.")
)
