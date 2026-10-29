package bootstrap

import "github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"

// The platform's request limits, each built once from here and reported by
// GET /v1/tenants/{tenantID}/rate-limits, so the two can't drift apart.

// The default organisation, person and API-key buckets, which are also their
// ceilings: an organisation may tighten them, never lift them.
var (
	tenantLimitDefault = ratelimits.Bucket{Rate: 100, Capacity: 500}
	userLimitDefault   = ratelimits.Bucket{Rate: 30, Capacity: 100}
	apiKeyLimitDefault = ratelimits.Bucket{Rate: 50, Capacity: 200}
)

// The built-in limits, the same for every organisation and not changeable.
var (
	loginLimit = ratelimits.BuiltInLimit{Name: "public", Per: "ip", Bucket: ratelimits.Bucket{Rate: 5, Capacity: 20},
		Applies: "Unauthenticated /v1 routes: sign-in, sign-up, recovery, invitations and the hosted pages' calls"}
	tokenLimit = ratelimits.BuiltInLimit{Name: "token", Per: "ip", Bucket: ratelimits.Bucket{Rate: 50, Capacity: 200},
		Applies: "The OAuth token endpoints, which serve an application's exchanges for all its users"}
	credentialLimit = ratelimits.BuiltInLimit{Name: "directory_credentials", Per: "ip", Bucket: ratelimits.Bucket{Rate: 5, Capacity: 20},
		Applies: "LDAP sign-in outside /v1"}
	protocolLimit = ratelimits.BuiltInLimit{Name: "protocol", Per: "ip", Bucket: ratelimits.Bucket{Rate: 50, Capacity: 200},
		Applies: "OIDC, SCIM and SAML protocol routes outside /v1"}
	sensitiveLimit = ratelimits.BuiltInLimit{Name: "sensitive", Per: "user", Bucket: ratelimits.Bucket{Rate: 0.1, Capacity: 5},
		Applies: "Sending a code to an address the caller gives, and checking a password"}
	pairingLimit = ratelimits.BuiltInLimit{Name: "device_pairing", Per: "ip", Bucket: ratelimits.Bucket{Rate: 0.1, Capacity: 5},
		Applies: "Linking a phone with a pairing code"}
	magicAddressLimit = ratelimits.BuiltInLimit{Name: "magic_link_address", Per: "address", Bucket: ratelimits.Bucket{Rate: 1.0 / 300, Capacity: 3},
		Applies: "Magic links sent to one email address"}
	magicCallerLimit = ratelimits.BuiltInLimit{Name: "magic_link_caller", Per: "ip", Bucket: ratelimits.Bucket{Rate: 1.0 / 60, Capacity: 10},
		Applies: "Magic links one caller asks for"}
	resetAddressLimit = ratelimits.BuiltInLimit{Name: "password_reset_address", Per: "address", Bucket: ratelimits.Bucket{Rate: 1.0 / 300, Capacity: 3},
		Applies: "Password-reset emails sent to one address"}
)

// builtInLimits lists the built-in limits for the API, in the order shown.
var builtInLimits = []ratelimits.BuiltInLimit{
	loginLimit, tokenLimit, credentialLimit, protocolLimit, sensitiveLimit,
	pairingLimit, magicAddressLimit, magicCallerLimit, resetAddressLimit,
}
