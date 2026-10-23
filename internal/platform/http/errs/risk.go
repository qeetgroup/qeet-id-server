package errs

// Risk (adaptive-access) error codes for the `internal/access/risk` bounded
// context — per-tenant IP allow/deny rules and their evaluation. Prefixed
// Risk* so nothing collides with other domains.
const (
	CodeRiskCIDRInvalid        = "risk.cidr_invalid"
	CodeRiskRuleActionInvalid  = "risk.rule_action_invalid"
	CodeRiskRulesLockOutCaller = "risk.rules_lock_out_caller"
)

var (
	ErrRiskCIDRInvalid        = New(CodeRiskCIDRInvalid, "Enter a valid IP address or CIDR range (for example 203.0.113.0/24).")
	ErrRiskRuleActionInvalid  = New(CodeRiskRuleActionInvalid, `A rule's action must be "allow" or "deny".`)
	ErrRiskRulesLockOutCaller = New(CodeRiskRulesLockOutCaller, "This change would block the address you're making it from, and lock you out. Add an allow rule that covers it first.")
)
