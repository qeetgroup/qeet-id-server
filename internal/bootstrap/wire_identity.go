package bootstrap

import (
	"cmp"
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/group"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/branding"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/identity/verification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// identityServices are the identity context's: people, organizations,
// verification, invitations, groups and verified domains. Its branding is
// built with the shared message chain (infra).
type identityServices struct {
	organizationRepo    *organization.Repository
	userRepo            *user.Repository
	verifyService       *verification.Service
	inviteService       *invite.Service
	groupService        *group.Service
	domainVerifyService *domainverify.Service
}

// newIdentity builds the identity context's services.
func (w *wiring) newIdentity() *identityServices {
	return &identityServices{
		organizationRepo: organization.NewRepository(w.pool),
		userRepo:         user.NewRepository(w.pool),
		verifyService:    verification.NewService(w.pool, w.sender, 10*time.Minute),
		inviteService:    invite.NewService(w.pool, w.sender, 14*24*time.Hour, w.cfg.AppBaseURL),
		groupService:     group.NewService(w.pool),
		// The custom domain, so its plan gate can be wired.
		domainVerifyService: domainverify.NewService(w.pool, w.outboundPolicy),
	}
}

// wireIdentity connects the identity context's services to the rest.
func (w *wiring) wireIdentity() {
	w.organizationRepo.SetHostingRegion(cmp.Or(w.cfg.HostingRegion, w.cfg.AWSRegion)) // where every organization is created
	w.verifyService.SetPlan(w.entitlementSvc)                                         // SMS codes only on plans that include them
	if w.mail.routed {
		w.verifyService.SetDeliveryCheck(w.mail.transport.Configured) // refuse codes no provider can deliver
	}
	w.inviteService.SetGrantCheck(w.rbacRepo.CheckGrantRole) // an invitation's sender must still be able to give its role
	w.inviteService.SetPasswordRules(w.authPolicyService)    // invite accept
	w.inviteService.SetAcceptMethods(w.authPolicyService)    // which ways of accepting the acceptance screen offers
	w.inviteService.SetPlanLimiter(w.entitlementSvc)         // seats
	w.groupService.SetSeatGuard(w.inviteService)             // seats: a person's first role, through a group
	w.brandingRepo.SetPlanGate(w.entitlementSvc)             // custom branding
	w.brandingRepo.SetPublicBaseURL(w.cfg.PublicBaseURL)
	w.domainVerifyService.SetPlanGate(w.entitlementSvc)
	w.domainVerifyService.SetOwners(w.rbacRepo) // only owners name break-glass members
	// Domain capture: an address on a verified domain with SSO on, in an
	// organization with an active SAML or LDAP connection, signs in only there,
	// except break-glass members and the administrators SSO never adopts.
	w.domainVerifyService.SetMemberPermissions(identitylink.MemberPermissions())
}

// identityHandlers serves the identity context.
func (w *wiring) identityHandlers(d *Deps) {
	d.Organization = &organization.Handler{Repo: w.organizationRepo, Validate: w.validate, AuthService: w.authService, Signals: w.sessionSignals, OwnerCheck: w.rbacRepo.IsOwner}
	d.User = &user.Handler{Repo: w.userRepo, Validate: w.validate, PasswordPolicy: w.authPolicyService.ValidateForOrganization, MFA: w.mfaService, SignIns: w.authService, Signals: w.sessionSignals, Mailer: w.sender, ActOnCheck: w.rbacRepo.CheckActOn,
		Roles: rbac.ImportRoles{Repo: w.rbacRepo, Seats: w.inviteService}}
	d.Verification = &verification.Handler{Service: w.verifyService}
	d.Invite = &invite.Handler{Service: w.inviteService, AuthService: w.authService, Validate: w.validate, GrantCheck: w.rbacRepo.CheckGrantRole}
	d.Branding = &branding.Handler{Repo: w.brandingRepo}
	d.Group = &group.Handler{Service: w.groupService, GrantCheck: w.rbacRepo.CheckGrantGroup, ActOnCheck: w.rbacRepo.CheckActOn, ReadsRoles: rbac.CallerHolds(w.rbacRepo, "role.read")}
	d.DomainVerify = &domainverify.Handler{Service: w.domainVerifyService}
}

// organizationDeletionsJob deletes each organization whose scheduled deletion
// is due, announcing the sessions it ends through signals.
func organizationDeletionsJob(pool *pgxpool.Pool, signals *sessionsignal.Signaller) worker.Scheduled {
	return worker.Scheduled{
		Name:     "organization-deletions",
		Interval: 15 * time.Minute,
		Run: func(ctx context.Context) error {
			n, err := organization.DeleteDue(postgres.AcrossOrganizations(ctx), organization.NewRepository(pool), signals)
			if n > 0 {
				slog.Info("organizations deleted as scheduled", "deleted", n)
			}
			return err
		},
	}
}

// identityPermissions are the identity context's routes and the user permission
// each needs, as userPermissionMap lists them.
func identityPermissions() map[string]string {
	return map[string]string{
		// Organizations (GET /v1/organizations lists the caller's own memberships — ungated).
		"GET /v1/organizations/{organizationID}":                  "organization.read",
		"PATCH /v1/organizations/{organizationID}":                "organization.write",
		"DELETE /v1/organizations/{organizationID}":               "organization.delete",
		"POST /v1/organizations/{organizationID}/deletion/cancel": "organization.delete",

		// Users.
		"GET /v1/users":                    "user.read",
		"GET /v1/users/stats":              "user.read",
		"GET /v1/users/trends":             "user.read",
		"POST /v1/users":                   "user.write",
		"POST /v1/users/bulk":              "user.write",
		"POST /v1/users/bulk/import":       "user.write",
		"GET /v1/users/deleted":            "user.read",
		"GET /v1/users/suspended":          "user.read",
		"POST /v1/users/{id}/reactivate":   "user.suspend",
		"PUT /v1/users/{id}/suspension":    "user.suspend",
		"GET /v1/users/{id}":               "user.read",
		"PATCH /v1/users/{id}":             "user.write",
		"DELETE /v1/users/{id}":            "user.delete",
		"DELETE /v1/users/{id}/membership": "user.delete",
		"POST /v1/users/{id}/restore":      "user.delete",
		"DELETE /v1/users/{id}/purge":      "user.delete",
		"POST /v1/users/{id}/password":     "user.credentials",
		"DELETE /v1/users/{id}/mfa":        "user.credentials", // admin MFA reset

		// User 360 — per-user admin read surfaces + force sign-out (see user360.go).
		"GET /v1/users/{id}/security":                                               "user.read",
		"GET /v1/users/{id}/sessions":                                               "user.read",
		"GET /v1/users/{id}/access":                                                 "user.read",
		"POST /v1/users/{id}/sessions/revoke-all":                                   "session.revoke",
		"DELETE /v1/organizations/{organizationID}/users/{id}/sessions/{sessionID}": "session.revoke",
		"GET /v1/organizations/{organizationID}/users/{id}/passkeys":                "user.read",
		"GET /v1/organizations/{organizationID}/users/{id}/sign-ins":                "audit.read",
		"DELETE /v1/organizations/{organizationID}/users/{id}/passkeys/{passkeyID}": "user.credentials",
		"PUT /v1/users/{id}/mfa-required":                                           "user.credentials",

		// Invites (inviting/removing members is user management).
		"POST /v1/invites": "member.invite",
		"GET /v1/organizations/{organizationID}/invites": "user.read",
		"POST /v1/invites/{id}/resend":                   "member.invite",
		"DELETE /v1/invites/{id}":                        "member.invite",

		// Groups.
		"POST /v1/groups": "group.write",
		"GET /v1/organizations/{organizationID}/groups": "group.read",
		"DELETE /v1/groups/{id}":                        "group.write",
		"PATCH /v1/groups/{id}":                         "group.write",
		"POST /v1/groups/{id}/members/{userID}":         "group.write",
		"DELETE /v1/groups/{id}/members/{userID}":       "group.write",
		"GET /v1/groups/{id}/members":                   "group.read",
		// Reusable group-shape templates and bulk import. Applying a template
		// and importing both create groups, so they take the write permission.
		"GET /v1/groups/templates":             "group.read",
		"POST /v1/groups/templates":            "group.write",
		"DELETE /v1/groups/templates/{id}":     "group.write",
		"POST /v1/groups/templates/{id}/apply": "group.write",
		"POST /v1/groups/import":               "group.write",

		// Branding.
		"PUT /v1/organizations/{organizationID}/branding": "branding.write",
		"GET /v1/organizations/{organizationID}/branding": "organization.read",

		// Verified domains affect hosted authentication routing.
		"GET /v1/organizations/{organizationID}/domains":              "connection.read",
		"POST /v1/organizations/{organizationID}/domains":             "connection.write",
		"POST /v1/organizations/{organizationID}/domains/{id}/verify": "connection.write",
		"DELETE /v1/organizations/{organizationID}/domains/{id}":      "connection.write",
		"PATCH /v1/organizations/{organizationID}/domains/{id}":       "connection.write",
		"GET /v1/organizations/{organizationID}/login-domain":         "connection.read",
		"POST /v1/organizations/{organizationID}/login-domain/check":  "connection.read",
		// Members who keep their own sign-in methods on a domain that requires
		// single sign-on; changing them is also owner-only (domainverify).
		"GET /v1/organizations/{organizationID}/break-glass-members":             "connection.read",
		"PUT /v1/organizations/{organizationID}/break-glass-members/{userID}":    "connection.write",
		"DELETE /v1/organizations/{organizationID}/break-glass-members/{userID}": "connection.write",
	}
}

// identityUserOnlyRoutes are the identity context's routes of a person's own account or
// resources, which RoutePolicies makes user-only.
func identityUserOnlyRoutes() []string {
	return []string{
		"GET /v1/me",
		"PATCH /v1/me",
		"GET /v1/organizations",
		"GET /v1/me/organizations",
		"POST /v1/organizations",
		"GET /v1/me/invites",
		"POST /v1/me/invites/accept",
		"POST /v1/me/invites/{id}/accept",
		"POST /v1/me/invites/{id}/decline",
		"POST /v1/users/{id}/verify/email/start",
		"POST /v1/users/{id}/verify/email/confirm",
		"POST /v1/users/{id}/verify/phone/start",
		"POST /v1/users/{id}/verify/phone/confirm",
		"POST /v1/me/email/change/start",
		"POST /v1/me/email/change/confirm",
	}
}

// identityStepUps are the identity context's routes that need a recent step-up, as
// StepUpRoutes lists them.
func identityStepUps() map[string]mfa.StepUpRule {
	return stepUps(
		[]string{
			// The address password resets and invitations go to.
			"POST /v1/me/email/change/start",
		},
		[]string{
			// A member's second factors and password.
			"PUT /v1/users/{id}/mfa-required",
			"DELETE /v1/users/{id}/mfa",
			"DELETE /v1/organizations/{organizationID}/users/{id}/passkeys/{passkeyID}",
			"POST /v1/users/{id}/password",

			// The domains that route to single sign-on, and who keeps their own
			// sign-in on them.
			"POST /v1/organizations/{organizationID}/domains",
			"PATCH /v1/organizations/{organizationID}/domains/{id}",
			"DELETE /v1/organizations/{organizationID}/domains/{id}",
			"PUT /v1/organizations/{organizationID}/break-glass-members/{userID}",
			"DELETE /v1/organizations/{organizationID}/break-glass-members/{userID}",

			// Handing out authority: who is in a group, and who is invited.
			"POST /v1/groups/{id}/members/{userID}",
			"DELETE /v1/groups/{id}/members/{userID}",
			"DELETE /v1/groups/{id}",
			"POST /v1/invites",

			// Bringing an account back.
			"POST /v1/users/{id}/reactivate",
			"POST /v1/users/{id}/restore",

			// Destroying an organization or an account. Updating the organization
			// can suspend it, which locks every member out.
			"DELETE /v1/organizations/{organizationID}",
			"PATCH /v1/organizations/{organizationID}",
			"DELETE /v1/users/{id}",
			"DELETE /v1/users/{id}/membership",
			"DELETE /v1/users/{id}/purge",
		},
	)
}
