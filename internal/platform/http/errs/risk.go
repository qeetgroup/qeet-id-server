package errs

// Risk (adaptive-access) error codes for the `internal/access/risk` bounded
// context — per-tenant IP allow/deny rules and their evaluation. Prefixed
// Risk* so nothing collides with other domains.
const (
	CodeRiskCIDRInvalid = "risk.cidr_invalid"
)

var (
	ErrRiskCIDRInvalid = New(CodeRiskCIDRInvalid, "Enter a valid IP address or CIDR range (for example 203.0.113.0/24).")
)
