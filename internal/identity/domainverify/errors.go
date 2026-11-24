package domainverify

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeNotMember = "domainverify.not_member"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrExists    = errs.New("domainverify.exists", errs.KindConflict, "This domain has already been added.")
	ErrNotFound  = errs.New("domainverify.not_found", errs.KindNotFound, "That domain doesn't exist.")
	ErrNotMember = errs.New(CodeNotMember, errs.KindNotFound, "That person isn't a member of this organization.")
	// ErrDNSRecordMissing is retryable: DNS changes take time to propagate.
	ErrDNSRecordMissing = errs.New("domainverify.dns_record_missing", errs.KindUnprocessable, "We couldn't find the verification record yet. DNS changes can take a few minutes to propagate — add the TXT record and try again.").AsRetryable()
)
