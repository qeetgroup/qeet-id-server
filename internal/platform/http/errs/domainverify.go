package errs

// Domain-verification error codes — stable, namespaced machine identifiers for
// the internal/identity/domainverify domain (claim + prove ownership of an email
// domain via a DNS TXT record). Clients branch and localize on these (never on
// the message text). Once shipped, a code MUST NOT change. Every identifier is
// prefixed with the `domainverify` domain so it never collides with another
// bounded context.
const (
	CodeDomainVerifyInvalidDomain    = "domainverify.invalid_domain"
	CodeDomainVerifyExists           = "domainverify.exists"
	CodeDomainVerifyDNSRecordMissing = "domainverify.dns_record_missing"
	CodeDomainVerifyClaimedByOther   = "domainverify.claimed_by_other"
	CodeDomainVerifyNotFound         = "domainverify.not_found"
)

// Domain-verification errors. The Message is what the end user sees — edit
// wording here, in one place. ErrDomainVerifyDNSRecordMissing is retryable: DNS
// changes take time to propagate, so a later retry can plausibly succeed.
var (
	ErrDomainVerifyInvalidDomain    = New(CodeDomainVerifyInvalidDomain, "Enter a valid domain, e.g. acme.com.")
	ErrDomainVerifyExists           = New(CodeDomainVerifyExists, "This domain has already been added.")
	ErrDomainVerifyDNSRecordMissing = New(CodeDomainVerifyDNSRecordMissing, "We couldn't find the verification record yet. DNS changes can take a few minutes to propagate — add the TXT record and try again.").AsRetryable()
	ErrDomainVerifyClaimedByOther   = New(CodeDomainVerifyClaimedByOther, "This domain is already verified by another organization.")
	ErrDomainVerifyNotFound         = New(CodeDomainVerifyNotFound, "That domain doesn't exist.")
)
