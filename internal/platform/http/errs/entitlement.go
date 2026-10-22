package errs

// Plan entitlement error codes: a feature not in the tenant's plan
// (upgrade_required) or a resource cap reached (plan_limit). Both map to 402.
const (
	CodeUpgradeRequired = "billing.upgrade_required"
	CodePlanLimit       = "billing.plan_limit"
)

var (
	ErrUpgradeRequired = New(CodeUpgradeRequired, "This feature isn't included in your plan. Upgrade to unlock it.") // metadata: feature, plan
	ErrPlanLimit       = New(CodePlanLimit, "You've reached your plan's limit. Upgrade to add more.")                // metadata: resource, limit, plan
)
