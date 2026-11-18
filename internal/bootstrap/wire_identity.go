package bootstrap

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
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

// newDirectories builds the repositories of organizations, people and roles,
// which need nothing but the database and which the other contexts are built
// from.
func (w *wiring) newDirectories() error {
	w.identityServices = &identityServices{
		organizationRepo: organization.NewRepository(w.pool, cmp.Or(w.cfg.HostingRegion, w.cfg.AWSRegion)),
		userRepo:         user.NewRepository(w.pool),
	}
	w.accessServices = &accessServices{rbacRepo: rbac.NewRepository(w.pool)}
	return nil
}

// newIdentity builds the identity context's services, after the
// authentication policy they check passwords and sign-in methods with.
func (w *wiring) newIdentity() error {
	policies, err := authpolicy.NewService(w.pool, breachChecker(w.cfg))
	if err != nil {
		return fmt.Errorf("authentication policy: %w", err)
	}
	w.authPolicyService = policies
	id := w.identityServices
	// The invitation's sender must still be able to give its role when it is
	// accepted; its seats are the plan's.
	if id.inviteService, err = invite.NewService(w.pool, invite.Deps{
		Sender: w.sender, TTL: 14 * 24 * time.Hour, BaseAppURL: w.cfg.AppBaseURL,
		Rules: policies, Methods: policies, Limits: w.entitlementSvc, Grants: w.rbacRepo.CheckGrantRole,
	}); err != nil {
		return fmt.Errorf("invitations: %w", err)
	}
	// Seats: a person's first role, through a group.
	if id.groupService, err = group.NewService(w.pool, id.inviteService); err != nil {
		return fmt.Errorf("groups: %w", err)
	}
	// SMS codes only on plans that include them, and no code a provider can't
	// deliver.
	if id.verifyService, err = verification.NewService(w.pool, w.sender, 10*time.Minute, w.entitlementSvc, w.deliverable()); err != nil {
		return fmt.Errorf("verification: %w", err)
	}
	// Domain capture: an address on a verified domain with SSO on, in an
	// organization with an active SAML or LDAP connection, signs in only there,
	// except break-glass members, whom only owners name, and the administrators
	// SSO never adopts.
	if id.domainVerifyService, err = domainverify.NewService(w.pool, domainverify.Deps{
		Gate: w.entitlementSvc, Owners: w.rbacRepo, MemberPermissions: identitylink.MemberPermissions(),
		Outbound: w.outboundPolicy,
	}); err != nil {
		return fmt.Errorf("domain verification: %w", err)
	}
	return nil
}

// deliverable is the check that a channel can deliver a code: the routed
// transport's, or, with mail not routed (the log sender of development),
// every channel.
func (w *wiring) deliverable() func(channel string) bool {
	if w.mail.routed {
		return w.mail.transport.Configured
	}
	return func(string) bool { return true }
}

// identityHandlers serves the identity context.
func (w *wiring) identityHandlers(d *Deps) error {
	d.Organization = &organization.Handler{Repo: w.organizationRepo, Validate: w.validate, AuthService: w.authService, Signals: w.sessionSignals, OwnerCheck: w.rbacRepo.IsOwner}
	d.User = &user.Handler{Repo: w.userRepo, Validate: w.validate, PasswordPolicy: w.authPolicyService.ValidateForOrganization, MFA: w.mfaService, SignIns: w.authService, Signals: w.sessionSignals, Mailer: w.sender, ActOnCheck: w.rbacRepo.CheckActOn,
		Roles: rbac.ImportRoles{Repo: w.rbacRepo, Seats: w.inviteService}}
	d.Verification = &verification.Handler{Service: w.verifyService, Throttle: w.sensitiveThrottle}
	d.Invite = &invite.Handler{Service: w.inviteService, AuthService: w.authService, Validate: w.validate, GrantCheck: w.rbacRepo.CheckGrantRole}
	d.Branding = &branding.Handler{Repo: w.brandingRepo}
	d.Group = &group.Handler{Service: w.groupService, GrantCheck: w.rbacRepo.CheckGrantGroup, ActOnCheck: w.rbacRepo.CheckActOn, ReadsRoles: rbac.CallerHolds(w.rbacRepo, "role.read")}
	d.DomainVerify = &domainverify.Handler{Service: w.domainVerifyService}
	return errors.Join(d.Organization.Check(), d.User.Check(), d.Verification.Check())
}

// organizationDeletionsJob deletes each organization whose scheduled deletion
// is due, announcing the sessions it ends through signals.
func organizationDeletionsJob(pool *pgxpool.Pool, signals *sessionsignal.Signaller) worker.Scheduled {
	return worker.Scheduled{
		Name:     "organization-deletions",
		Interval: 15 * time.Minute,
		Run: func(ctx context.Context) error {
			n, err := organization.DeleteDue(postgres.AcrossOrganizations(ctx), organization.NewRepository(pool, ""), signals) // deleting creates nothing, so no region
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
