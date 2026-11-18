package abac

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeConditionInvalid = "abac.condition_invalid"
	CodePolicyLocksOut   = "abac.policy_locks_out"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrNameRequired         = errs.New("abac.name_required", errs.KindUnprocessable, "Enter a name for the policy.")
	ErrEffectInvalid        = errs.New("abac.effect_invalid", errs.KindUnprocessable, "Effect must be either \"allow\" or \"deny\".")
	ErrResourceTypeRequired = errs.New("abac.resource_type_required", errs.KindUnprocessable, "Specify the resource type this policy applies to.")
	ErrActionRequired       = errs.New("abac.action_required", errs.KindUnprocessable, "Specify the action this policy applies to.")
	ErrConditionInvalid     = errs.New(CodeConditionInvalid, errs.KindUnprocessable, "The policy condition is invalid.")
	ErrPolicyNameExists     = errs.New("abac.policy_name_exists", errs.KindConflict, "A policy with that name already exists.")
	ErrPolicyLocksOut       = errs.New(CodePolicyLocksOut, errs.KindConflict, "This deny policy would stop you changing policies, so nobody could undo it. Narrow its condition so it doesn't match you, or limit it to other resources or actions.")
)
