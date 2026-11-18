package bootstrap

import "github.com/qeetgroup/qeet-id-server/internal/access/mfa"

// StepUpRoutes lists the authenticated routes that need a recent step-up, so a
// stolen access token alone can't change factors, credentials, secrets, policy or
// authority. StepUpOrRecentSignIn applies to a person's own factors and sign-in
// methods; everything else is StepUpAlways, which machine principals can never
// meet. Each context lists its own routes (wire_<context>.go).
func StepUpRoutes() map[string]mfa.StepUpRule {
	return routeTable(accessStepUps(), identityStepUps(), federationStepUps(), developerStepUps(), operationsStepUps())
}

// stepUps is the step-up rule of each route listed: StepUpOrRecentSignIn for
// recentSignIn, StepUpAlways for always.
func stepUps(recentSignIn, always []string) map[string]mfa.StepUpRule {
	routes := map[string]mfa.StepUpRule{}
	for _, route := range recentSignIn {
		routes[route] = mfa.StepUpOrRecentSignIn
	}
	for _, route := range always {
		routes[route] = mfa.StepUpAlways
	}
	return routes
}
