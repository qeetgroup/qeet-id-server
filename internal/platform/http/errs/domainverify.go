package errs

// Domain verification error codes: proving ownership of an email domain with a
// DNS TXT record.
const (
	CodeDomainVerifyInvalidDomain  = "domainverify.invalid_domain"
	CodeDomainVerifyClaimedByOther = "domainverify.claimed_by_other"
)

// Domain-verification errors. The Message is what the end user sees — edit
// wording here, in one place. ErrDomainVerifyDNSRecordMissing is retryable: DNS
// changes take time to propagate, so a later retry can plausibly succeed.
var (
	ErrDomainVerifyInvalidDomain    = New(CodeDomainVerifyInvalidDomain, KindUnprocessable, "Enter a valid domain, e.g. acme.com.")
	ErrDomainVerifyDNSRecordMissing = New("domainverify.dns_record_missing", KindUnprocessable, "We couldn't find the verification record yet. DNS changes can take a few minutes to propagate — add the TXT record and try again.").AsRetryable()
	ErrDomainVerifyClaimedByOther   = New(CodeDomainVerifyClaimedByOther, KindConflict, "This domain is already verified by another organization.")
)
