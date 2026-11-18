package ipallow

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeRiskCIDRInvalid        = "risk.cidr_invalid"
	CodeRiskRuleActionInvalid  = "risk.rule_action_invalid"
	CodeRiskRulesLockOutCaller = "risk.rules_lock_out_caller"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrRiskCIDRInvalid        = errs.New(CodeRiskCIDRInvalid, errs.KindUnprocessable, "Enter a valid IP address or CIDR range (for example 203.0.113.0/24).")
	ErrRiskRuleActionInvalid  = errs.New(CodeRiskRuleActionInvalid, errs.KindUnprocessable, `A rule's action must be "allow" or "deny".`)
	ErrRiskRulesLockOutCaller = errs.New(CodeRiskRulesLockOutCaller, errs.KindConflict, "This change would block the address you're making it from, and lock you out. Add an allow rule that covers it first.")
)
