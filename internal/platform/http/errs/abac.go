package errs

// ABAC (attribute-based access control) error codes — stable, namespaced
// machine identifiers for policy validation and management. Clients branch and
// localize on these, never on the message text. Once shipped, a code MUST NOT
// change.
const (
	CodeABACNameRequired         = "abac.name_required"
	CodeABACEffectInvalid        = "abac.effect_invalid"
	CodeABACResourceTypeRequired = "abac.resource_type_required"
	CodeABACActionRequired       = "abac.action_required"
	CodeABACConditionInvalid     = "abac.condition_invalid"
	CodeABACPolicyNameExists     = "abac.policy_name_exists"
)

// ABAC errors. The Message is what the admin authoring a policy sees.
var (
	ErrABACNameRequired         = New(CodeABACNameRequired, "Enter a name for the policy.")
	ErrABACEffectInvalid        = New(CodeABACEffectInvalid, "Effect must be either \"allow\" or \"deny\".")
	ErrABACResourceTypeRequired = New(CodeABACResourceTypeRequired, "Specify the resource type this policy applies to.")
	ErrABACActionRequired       = New(CodeABACActionRequired, "Specify the action this policy applies to.")
	ErrABACConditionInvalid     = New(CodeABACConditionInvalid, "The policy condition is invalid.")
	ErrABACPolicyNameExists     = New(CodeABACPolicyNameExists, "A policy with that name already exists.")
)
