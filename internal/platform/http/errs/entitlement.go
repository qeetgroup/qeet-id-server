package errs

// Plan-entitlement error codes — raised when an action is blocked by the
// tenant's subscription plan. Two shapes: a boolean feature not included in the
// plan (upgrade_required) and a numeric resource cap reached (plan_limit).
// Clients branch on these stable codes to show an "Upgrade" prompt instead of a
// generic error. Both map to 402 Payment Required (see error_status_entitlement.go).
const (
	CodeUpgradeRequired = "billing.upgrade_required"
	CodePlanLimit       = "billing.plan_limit"
)

var (
	// ErrUpgradeRequired: a plan-gated feature (SSO, SCIM, LDAP, webhooks, …) is
	// not included in the tenant's plan. Attach WithMetadata({"feature":..,"plan":..}).
	ErrUpgradeRequired = New(CodeUpgradeRequired, "This feature isn't included in your plan. Upgrade to unlock it.")
	// ErrPlanLimit: a numeric resource cap (seats, apps, api_keys, …) is reached.
	// Attach WithMetadata({"resource":..,"limit":N,"plan":..}).
	ErrPlanLimit = New(CodePlanLimit, "You've reached your plan's limit. Upgrade to add more.")
)
