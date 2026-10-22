package errs

// ABAC (attribute-based access control) policy error codes.
const (
	CodeABACNameRequired         = "abac.name_required"
	CodeABACEffectInvalid        = "abac.effect_invalid"
	CodeABACResourceTypeRequired = "abac.resource_type_required"
	CodeABACActionRequired       = "abac.action_required"
	CodeABACConditionInvalid     = "abac.condition_invalid"
	CodeABACPolicyNameExists     = "abac.policy_name_exists"
	CodeABACPolicyLocksOut       = "abac.policy_locks_out"
)

// ABAC errors. The Message is what the admin authoring a policy sees.
var (
	ErrABACNameRequired         = New(CodeABACNameRequired, "Enter a name for the policy.")
	ErrABACEffectInvalid        = New(CodeABACEffectInvalid, "Effect must be either \"allow\" or \"deny\".")
	ErrABACResourceTypeRequired = New(CodeABACResourceTypeRequired, "Specify the resource type this policy applies to.")
	ErrABACActionRequired       = New(CodeABACActionRequired, "Specify the action this policy applies to.")
	ErrABACConditionInvalid     = New(CodeABACConditionInvalid, "The policy condition is invalid.")
	ErrABACPolicyNameExists     = New(CodeABACPolicyNameExists, "A policy with that name already exists.")
	ErrABACPolicyLocksOut       = New(CodeABACPolicyLocksOut, "This deny policy would stop you changing policies, so nobody could undo it. Narrow its condition so it doesn't match you, or limit it to other resources or actions.")
)
