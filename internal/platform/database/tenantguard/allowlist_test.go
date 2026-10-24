package tenantguard_test

// allowlist is the tenant-filter guard's exception list: one "path#Name  category:
// reason" line per entry, with # lines as comments. Entries are reported by
// their line in this file.
const allowlist = `
# Queries allowed to touch a tenant-owned table without mentioning tenant_id.
# tenantguard_test.go fails on any other such query, and on a line here that
# no longer matches one, so delete a line once its query is scoped or removed.
#
# Format: <path>#<name>  <category>: <reason>
#   queries.sql: <name> is the sqlc query name.
#   Go:          <name> is the enclosing function (Recv.Method for a method).
#
# Accounts in "user".users are global (email is unique platform-wide and
# membership lives in rbac.user_roles), so account reads by ID appear here.
#
# Categories:
#   secret-lookup      found by a token, code or secret hash only its holder has
#   session-scoped     the caller's own session or account, from a verified token
#   background-sweep   a scheduled job that works across every tenant by design
#   parent-scoped      the ID came from an earlier tenant-scoped read or check
#   global-client      an OIDC client by client_id, which is unique platform-wide
#   pre-tenant         sign-up or sign-in before a tenant applies
#   global-table-join  a global table joined to a tenant-owned one
#   platform-wide      one record for every tenant; callers show its tenant's fields to that tenant only
#   pending-review     not shown to be safe; needs a tenant condition or removal

cmd/seed/main.go#main  pre-tenant: local seed empties tables before creating tenants

internal/access/authentication/accountstatus.go#Service.refuseInactiveAccount  pre-tenant: sign-in checks the account it just verified
internal/access/authentication/mfalogin.go#Service.BeginMFAPasskey  secret-lookup: challenge found by its random MFA token
internal/access/authentication/mfalogin.go#Service.SendMFACode  secret-lookup: challenge found by its random MFA token
internal/access/authentication/mfalogin.go#Service.StartMFAPush  secret-lookup: challenge found by its random MFA token
internal/access/authentication/mfalogin.go#loadMFAChallenge  secret-lookup: challenge found by its random MFA token
internal/access/authentication/mfapolicy.go#Service.StartMFAEnrollment  secret-lookup: challenge found by its random MFA token
internal/access/authentication/queries.sql#DeleteMFALoginChallenge  pending-review: unused query; delete it or add a tenant condition
internal/access/authentication/queries.sql#DeleteTrustedDevicesForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/authentication/queries.sql#DenyBackchannelRequestsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/authentication/queries.sql#DenyDeviceAuthorizationsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/authentication/queries.sql#EndLoginSession  secret-lookup: login session found by its cookie hash
internal/access/authentication/queries.sql#ExpireAuthorizationCodesForLoginSession  session-scoped: the login session being ended
internal/access/authentication/queries.sql#GetClientTenant  global-client: client_id is unique platform-wide
internal/access/authentication/queries.sql#GetLoginSession  secret-lookup: session found by its cookie token hash; reads its own account's status
internal/access/authentication/queries.sql#IsSessionLiveForUser  session-scoped: the caller's own session and user
internal/access/authentication/queries.sql#IsSessionOfUser  session-scoped: the caller's own session and user
internal/access/authentication/queries.sql#LockUserForSessionRevocation  parent-scoped: locks an account its callers already checked
internal/access/authentication/queries.sql#PurgeEndedSessions  background-sweep: session cleanup job
internal/access/authentication/queries.sql#PurgeExpiredTrustedDevices  background-sweep: session cleanup job
internal/access/authentication/queries.sql#RevokeAllSessionsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/authentication/queries.sql#RevokeAppGrantsForLoginSession  session-scoped: the login session being ended
internal/access/authentication/queries.sql#RevokeAppGrantsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/authentication/queries.sql#RevokeOtherSessionsForUser  session-scoped: the caller's own other sessions
internal/access/authentication/queries.sql#RevokeSessionById  session-scoped: the session of the refresh token in use
internal/access/authentication/queries.sql#RevokeSessionForUser  session-scoped: only a session of the caller's own user
internal/access/authentication/queries.sql#SessionEnd  session-scoped: the caller's own session and user
internal/access/authentication/queries.sql#SpendAuthorizationCodesForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/authentication/queries.sql#SupersedeSession  session-scoped: the caller's own session, replaced on tenant switch
internal/access/authentication/queries.sql#TouchSession  session-scoped: the session of the verified access token
internal/access/authentication/queries.sql#UpdateSessionLastSeen  session-scoped: the session of the refresh token in use
internal/access/authentication/risksignin.go#Service.newRiskEmailCode  secret-lookup: challenge found by its random MFA token
internal/access/authentication/risksignin.go#Service.riskEmailChallenge  pre-tenant: sign-in reads the account it just verified
internal/access/authentication/risksignin.go#Service.sendRiskEmailCode  secret-lookup: challenge found by its random MFA token
internal/access/authentication/password.go#Service.ChangePassword  session-scoped: locks the caller's own account
internal/access/authentication/sessions.go#Service.ListSessionsPageFor  session-scoped: the caller's own sessions
internal/access/authentication/mfachallenge.go#Service.deferEnrollment  secret-lookup: challenge found by its random MFA token
internal/access/authentication/mfachallenge.go#Service.verifyAndConsumeMFAChallenge  secret-lookup: challenge found by its random MFA token
internal/access/authentication/switch.go#carrySecondFactor  session-scoped: the session issued in the same transaction
internal/access/authentication/sessionlimit.go#Service.enforceSessionLimit  parent-scoped: session IDs from the tenant-scoped list above
internal/access/authentication/signinaudit.go#Service.homeTenant  pre-tenant: files a failed sign-in under the account's home tenant
internal/access/authorization/rbac/queries.sql#GetRoleTenant  parent-scoped: scopedRole compares the role's tenant to httpx.RequireTenant
internal/access/mfa/totp.go#Service.ResetForUser  parent-scoped: the handler checks the user's home tenant first
internal/access/mfa/pairing.go#PurgeExpiredPushPairings  background-sweep: cleanup job for expired codes
internal/access/mfa/pairing.go#Service.ClaimPushPairing  secret-lookup: pairing found by its code hash
internal/access/mfa/pairing.go#Service.CreatePushPairing  session-scoped: the caller's own pairing codes
internal/access/mfa/pairing.go#Service.GetPushPairing  session-scoped: the caller's own pairing codes
internal/access/mfa/pairing.go#Service.WithdrawPushPairing  session-scoped: the caller's own pairing codes
internal/access/mfa/queries.sql#RecordStepUp  session-scoped: the caller's own session and user
internal/access/passkeys/queries.sql#GetUserForWebAuthn  pre-tenant: the caller's own account, or the one a passkey sign-in asserts
internal/access/passkeys/queries.sql#GetUserIDByEmail  pre-tenant: passkey sign-in finds the account by email
internal/access/recovery/queries.sql#GetMagicLinkAccount  pre-tenant: magic-link sign-in finds the account by email
internal/access/recovery/queries.sql#GetMagicLinkByToken  secret-lookup: link found by its token hash
internal/access/recovery/queries.sql#GetResetAccount  secret-lookup: account named by the reset token
internal/access/recovery/queries.sql#MarkMagicLinkUsed  secret-lookup: link found by its token hash
internal/access/recovery/queries.sql#RevokeUserSessions  pending-review: unused query; delete it or add a tenant condition
internal/access/recovery/queries.sql#VerifyEmailByReset  secret-lookup: account named by the reset token
internal/access/recovery/recovery.go#Service.StartPasswordReset  pre-tenant: password reset finds the account by email
internal/access/threat/risk/history.go#PurgeSignInHistory  background-sweep: retention job

internal/developer/agents/queries.sql#GetAgentForToken  secret-lookup: the agent's secret is verified against this row
internal/developer/agents/queries.sql#GetAgentStatusByID  session-scoped: agent named by the verified access token
internal/developer/api-keys/queries.sql#TouchAPIKeyLastUsed  secret-lookup: the key just verified by its secret
internal/developer/api-keys/queries.sql#VerifyAPIKey  secret-lookup: key found by prefix and checked against its secret hash
internal/developer/auth-hooks/authhook.go#Service.Run  parent-scoped: hook ID from the tenant-scoped read above
internal/developer/credentials/tokenvault/queries.sql#DeleteConnectState  secret-lookup: single-use random OAuth state
internal/developer/credentials/vc/queries.sql#GetCredentialRevocation  parent-scoped: ID of a credential whose signature was just verified
internal/developer/principal/queries.sql#GetServicePrincipalForAuth  secret-lookup: the client secret is verified against this row
internal/developer/webhooks/webhook.go#Service.tick  background-sweep: delivery worker for every tenant

internal/federation/adminportal/adminportal.go#Service.Exchange  secret-lookup: link found by its token hash
internal/federation/adminportal/adminportal.go#Service.ResolveSession  secret-lookup: session found by its token hash
internal/federation/adminportal/queries.sql#GetAdminPortalLinkByHash  pending-review: unused query; delete it or add a tenant condition
internal/federation/adminportal/queries.sql#TouchAdminPortalLinkUsed  pending-review: unused query; delete it or add a tenant condition
internal/federation/identitylink/identitylink.go#AddressVerified  pre-tenant: federated sign-in checks the account it found
internal/federation/ldap/ldap.go#Service.getFull  parent-scoped: re-encrypts the connection row just read
internal/federation/ldap/queries.sql#GetUserByEmail  pre-tenant: federated sign-in finds the account by email
internal/federation/ldap/queries.sql#TouchLdapLastLogin  parent-scoped: connection row read for this sign-in
internal/federation/oidc/queries.sql#ApproveCIBARequest  parent-scoped: request locked and checked against the caller
internal/federation/oidc/queries.sql#ApproveDevice  secret-lookup: request found by its user code
internal/federation/oidc/queries.sql#ClaimLogoutDeliveries  background-sweep: back-channel logout worker
internal/federation/oidc/queries.sql#ConsumeAuthorizationCode  secret-lookup: by client and authorization code hash
internal/federation/oidc/queries.sql#ConsumeCIBARequest  secret-lookup: request found by its auth_req_id hash
internal/federation/oidc/queries.sql#ConsumeDeviceCode  secret-lookup: request found by its device code hash
internal/federation/oidc/queries.sql#DenyCIBARequest  parent-scoped: request locked and checked against the caller
internal/federation/oidc/queries.sql#DenyDevice  secret-lookup: request found by its user code
internal/federation/oidc/queries.sql#GetAccountStanding  parent-scoped: account named by the grant in use
internal/federation/oidc/queries.sql#GetClientForAuth  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetClientGrantTypes  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetClientName  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetClientPostLogoutURIs  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetClientRedirectInfo  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetClientTenantAndScopes  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetDeviceByUserCode  secret-lookup: request found by its user code
internal/federation/oidc/queries.sql#GetRefreshTokenForIntrospect  secret-lookup: token row found by its hash, then bound to the calling client
internal/federation/oidc/queries.sql#GetUserinfo  session-scoped: account named by the verified access token
internal/federation/oidc/queries.sql#ListPendingCIBA  session-scoped: the caller's own pending requests
internal/federation/oidc/queries.sql#LockCIBARequest  session-scoped: checked against the caller before any use
internal/federation/oidc/queries.sql#LockCIBARequestByHash  secret-lookup: request found by its auth_req_id hash
internal/federation/oidc/queries.sql#LockDeviceByCode  secret-lookup: request found by its device code hash
internal/federation/oidc/queries.sql#LockDeviceByUserCode  secret-lookup: request found by its user code
internal/federation/oidc/queries.sql#LockRefreshToken  secret-lookup: token row found by its hash
internal/federation/oidc/queries.sql#MarkAuthorizationCodeUsed  secret-lookup: by authorization code hash
internal/federation/oidc/queries.sql#MarkLogoutDelivered  background-sweep: back-channel logout worker
internal/federation/oidc/queries.sql#MarkLogoutDeliveryFailed  background-sweep: back-channel logout worker
internal/federation/oidc/queries.sql#MarkRefreshTokenUsed  secret-lookup: token row found by its hash
internal/federation/oidc/queries.sql#RevokeGrantFromCode  secret-lookup: by client and authorization code hash
internal/federation/oidc/queries.sql#RevokeRefreshTokenChain  global-client: client_id belongs to one tenant
internal/federation/oidc/queries.sql#RevokeRefreshTokenGrant  secret-lookup: by the authenticated client and its refresh token hash
internal/federation/oidc/queries.sql#SessionClients  session-scoped: clients of the login session being ended
internal/federation/oidc/queries.sql#TouchCIBAPollTime  secret-lookup: request found by its auth_req_id hash
internal/federation/oidc/queries.sql#TouchDevicePollTime  secret-lookup: request found by its device code hash
internal/federation/saml/queries.sql#ConsumeSamlLoginCode  secret-lookup: by login code hash
internal/federation/saml/queries.sql#GetSamlConnectionByID  pre-tenant: public SSO endpoints; the connection in the path names the tenant
internal/federation/saml/queries.sql#GetUserByEmail  pre-tenant: federated sign-in finds the account by email
internal/federation/saml/queries.sql#GetUserForIdP  session-scoped: the IdP session's user; its tenant is compared to the SP's
internal/federation/saml/queries.sql#MarkSamlLoginCodeUsed  secret-lookup: by login code hash
internal/federation/saml/queries.sql#TouchSamlLastLogin  parent-scoped: connection row read for this sign-in
internal/federation/saml/queries.sql#TouchSamlSPLastLogin  parent-scoped: service provider row read for this sign-in
internal/federation/saml/saml.go#Service.AllowsIdPInitiated  parent-scoped: connection ID from a read that checked it
internal/federation/scim/queries.sql#GetScimTokenTenant  secret-lookup: tenant named by the SCIM token hash
internal/federation/scim/queries.sql#TagProvisionedUser  parent-scoped: account created for the tenant in the same transaction
internal/federation/social/platform.go#Service.findOrCreatePlatformUser  pre-tenant: platform sign-in finds or creates the account
internal/federation/social/providers.go#Service.DeleteProvider  parent-scoped: provider ID from the tenant-scoped read above
internal/federation/social/providers.go#Service.UpdateProvider  parent-scoped: provider ID from the tenant-scoped read above
internal/federation/social/queries.sql#ConsumeSocialLoginCode  secret-lookup: by login code hash
internal/federation/social/queries.sql#ConsumeSocialOAuthState  secret-lookup: state found by its hash
internal/federation/social/queries.sql#DeleteExternalIdentityForUser  pending-review: unused query; delete it or add a tenant condition
internal/federation/social/queries.sql#GetUserByEmail  pre-tenant: social sign-in finds the account by email
internal/federation/social/queries.sql#ListExternalIdentitiesForUser  pending-review: unused query; delete it or add a tenant condition
internal/federation/social/queries.sql#MarkSocialLoginCodeUsed  secret-lookup: by login code hash
internal/federation/social/social.go#requireVerifiedAddress  pre-tenant: social sign-in checks the account it found

internal/identity/invitations/queries.sql#ActivateInvitedAccount  parent-scoped: account created for the invite in the same transaction
internal/identity/invitations/queries.sql#DeclineInviteForEmail  session-scoped: only invites to the caller's verified email
internal/identity/invitations/queries.sql#FindUserIDByEmail  pre-tenant: email is unique across all accounts
internal/identity/invitations/queries.sql#GetInboxEmail  session-scoped: the caller's own account
internal/identity/invitations/queries.sql#GetInviteByIDForAccept  session-scoped: accepted only for the caller's verified email, or a new account's tenant and email
internal/identity/invitations/queries.sql#GetInviteForAccept  secret-lookup: invite found by its token hash
internal/identity/invitations/queries.sql#GetUserEmailByID  session-scoped: the caller's own account
internal/identity/invitations/queries.sql#MarkInviteAccepted  parent-scoped: invite read under lock just before
internal/identity/invitations/queries.sql#MarkInviteExpired  parent-scoped: invite read under lock just before
internal/identity/tenant/queries.sql#IsEmailVerified  session-scoped: the caller's own account
internal/identity/users/queries.sql#GetUserByEmailGlobal  pre-tenant: password sign-in finds the account by email
internal/identity/users/queries.sql#GetUserByID  parent-scoped: callers pass their own, a signing-in or a tenant-checked account
internal/identity/users/queries.sql#MarkEmailVerified  pending-review: unused query; delete it or add a tenant condition
internal/identity/users/queries.sql#PurgeUser  parent-scoped: the handler checks the user's home tenant first
internal/identity/users/queries.sql#RestoreUser  parent-scoped: the handler checks the user's home tenant first
internal/identity/users/queries.sql#SetUserMfaRequired  parent-scoped: the handler checks the user's home tenant first
internal/identity/users/queries.sql#SoftDeleteUser  parent-scoped: SCIM checks the user belongs to the tenant first
internal/identity/users/queries.sql#SoftDeleteUserBy  parent-scoped: the handler checks the user's home tenant first
internal/identity/users/repository.go#Repository.update  parent-scoped: callers pass their own or a tenant-checked account
internal/identity/users/signinmethods.go#LockSignInMethods  parent-scoped: callers pass their own or a tenant-checked account
internal/identity/verification/queries.sql#EmailTakenByOther  session-scoped: the caller's email change; email is unique platform-wide
internal/identity/verification/queries.sql#GetUserEmail  session-scoped: the caller's own account
internal/identity/verification/queries.sql#GetUserPhone  session-scoped: the caller's own account
internal/identity/verification/queries.sql#MarkUserEmailVerified  session-scoped: the caller's own account
internal/identity/verification/queries.sql#MarkUserPhoneVerified  pending-review: unused query; delete it or add a tenant condition
internal/identity/verification/queries.sql#SetUserVerifiedPhone  session-scoped: the caller's own account
internal/identity/verification/queries.sql#UpdateUserEmail  session-scoped: the caller's own account

internal/operations/audit/anomaly/anomaly.go#Service.scoreOne  background-sweep: anomaly scoring job
internal/operations/audit/anomaly/queries.sql#ListUnscoredAuditEvents  background-sweep: anomaly scoring job
internal/operations/audit/anomaly/queries.sql#MarkAuditEventScored  background-sweep: anomaly scoring job
internal/operations/billing/checkout.go#Service.StartSignupCheckout  pre-tenant: sign-up checkout runs before the tenant exists
internal/operations/billing/checkout.go#Service.completeSignupCheckout  pre-tenant: completing the checkout creates the tenant
internal/operations/billing/queries.sql#CompleteCheckout  parent-scoped: checkout named by a signature-verified payment webhook or callback
internal/operations/billing/queries.sql#UpdateCheckoutFailed  parent-scoped: checkout inserted for the tenant just before
internal/operations/billing/queries.sql#UpdateCheckoutProviderRef  parent-scoped: checkout inserted for the tenant just before
internal/operations/email/editor.go#Handler.testEmail  session-scoped: sends to the caller's own verified email
internal/operations/gdpr/gdpr.go#Service.ExportSelf  session-scoped: the caller's own data export
internal/operations/gdpr/gdpr.go#Service.buildExport  background-sweep: export worker holding the request lease
internal/operations/gdpr/gdpr.go#Service.exportSweepTick  background-sweep: export worker holding the request lease
internal/operations/gdpr/gdpr.go#Service.purgeOne  background-sweep: purge worker holding the request lease
internal/operations/gdpr/gdpr.go#Service.tick  background-sweep: purge worker claiming due requests
internal/operations/gdpr/queries.sql#CompletePurgeRequest  pending-review: unused query; delete it or add a tenant condition
internal/operations/gdpr/queries.sql#FailExportRequest  pending-review: unused query; delete it or add a tenant condition
internal/operations/gdpr/queries.sql#PurgeUserPII  session-scoped: the caller erasing their own account
internal/operations/gdpr/queries.sql#ReadyExportRequest  pending-review: unused query; delete it or add a tenant condition
internal/operations/gdpr/queries.sql#RevokeUserSessions  pending-review: unused query; delete it or add a tenant condition
internal/operations/notifications/queries.sql#CountUnreadNotifications  session-scoped: the caller's own inbox; notifications belong to the account
internal/operations/notifications/queries.sql#ListNotifications  session-scoped: the caller's own inbox; notifications belong to the account
internal/operations/notifications/queries.sql#MarkAllNotificationsRead  session-scoped: the caller's own inbox; notifications belong to the account
internal/operations/retention/queries.sql#ListEnabledRetentionPolicies  background-sweep: retention job
internal/operations/siem/queries.sql#AdvanceLogSinkCursor  background-sweep: log forwarding job
internal/operations/siem/queries.sql#SetLogSinkError  background-sweep: log forwarding job
internal/operations/siem/siem.go#Service.forwardDue  background-sweep: log forwarding job

internal/platform/cache/ratelimit/tenant.go#TenantLimiter.GetAll  pending-review: unused method; lists every tenant's overrides
internal/platform/cache/ratelimit/tenant.go#TenantLimiter.LoadOverrides  background-sweep: startup load of every tenant's override into the limiter
internal/platform/events/sessionsignal/sessionsignal.go#EndUserSessions  parent-scoped: callers check the user's home tenant first, or erase the account
internal/platform/messaging/delivery/queries.sql#ActiveSuppression  platform-wide: an address's suppression stops every tenant's mail; only the causing tenant sees its detail
internal/platform/messaging/delivery/queries.sql#DeleteMessagesBefore  background-sweep: retention job
internal/platform/messaging/delivery/queries.sql#MessageByProviderID  parent-scoped: message named by a signature-verified SES notification
internal/platform/messaging/delivery/queries.sql#SetMessageStatus  parent-scoped: message found by its provider message ID just before
`
