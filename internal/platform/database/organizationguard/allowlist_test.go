package organizationguard_test

// allowlist is the organization-filter guard's exception list: one "path#Name  category:
// reason" line per entry, with # lines as comments. Entries are reported by
// their line in this file.
const allowlist = `
# Queries allowed to touch an organization-owned table without mentioning organization_id.
# organizationguard_test.go fails on any other such query, and on a line here that
# no longer matches one, so delete a line once its query is scoped or removed.
#
# Format: <path>#<name>  <category>: <reason>
#   queries.sql: <name> is the sqlc query name.
#   Go:          <name> is the enclosing function (Recv.Method for a method).
#
# Accounts in account.users are global (email is unique platform-wide and
# membership lives in rbac.user_roles), so account reads by ID appear here.
#
# Categories:
#   secret-lookup      found by a token, code or secret hash only its holder has
#   session-scoped     the caller's own session or account, from a verified token
#   background-sweep   a scheduled job that works across every organization by design
#   parent-scoped      the ID came from an earlier organization-scoped read or check
#   global-client      an OIDC client by client_id, which is unique platform-wide
#   pre-organization         sign-up or sign-in before an organization applies
#   global-table-join  a global table joined to an organization-owned one
#   platform-wide      one record for every organization; callers show its organization's fields to that organization only
#   pending-review     not shown to be safe; needs an organization condition or removal

internal/access/accountnotice/queries.sql#NoticeAddress  session-scoped: the account the change was made to, by its owner or on their account, read for its own address
internal/access/auth/queries.sql#AccountStanding  pre-organization: sign-in checks the account it just verified
internal/access/auth/queries.sql#HomeOrganization  pre-organization: files a failed sign-in under the account's home organization
internal/access/auth/queries.sql#AccountEmail  pre-organization: emails the account whose second-factor sign-in just locked
internal/access/auth/queries.sql#AccountEmailVerified  pre-organization: sign-in reads the account it just verified
internal/access/auth/queries.sql#VerifiedAccountEmail  pre-organization: sign-in reads the account it just verified
internal/access/auth/queries.sql#ForgetPushPairings  parent-scoped: the account whose address was just proved, everywhere it set up a credential
internal/access/auth/queries.sql#ForgetLinkedAccounts  parent-scoped: the account whose address was just proved, everywhere it set up a credential
internal/access/auth/queries.sql#ForgetSignInCodes  parent-scoped: the account whose address was just proved, everywhere it set up a credential
internal/access/auth/queries.sql#ForgetAPIKeys  parent-scoped: the account whose address was just proved, everywhere it set up a credential
internal/access/auth/queries.sql#EvictSessions  parent-scoped: session IDs from the organization-scoped LiveSessionsByUse
internal/access/auth/queries.sql#ContinueSession  session-scoped: the session issued in the same transaction, from one of the same person's
internal/access/auth/queries.sql#SessionCursorTime  session-scoped: the caller's own sessions
internal/access/auth/queries.sql#ListUserSessions  session-scoped: the caller's own sessions
internal/access/auth/queries.sql#CountUserSessions  session-scoped: the caller's own sessions
internal/access/auth/queries.sql#LockAccount  session-scoped: locks the caller's own account
internal/access/auth/queries.sql#DeleteMFALoginChallenge  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#LockMFAChallenge  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#LockMFAChallengeForProof  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#CountMFAChallengeFailure  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#CountMFACodeSent  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#UncountMFACodeSent  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#SetMFAChallengePasskeySession  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#SetMFAChallengePush  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#StartMFAChallengeEnrollment  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#IssueRiskEmailCode  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#WithdrawRiskEmailCode  secret-lookup: challenge found by its random MFA token
internal/access/auth/queries.sql#SignInClientName  global-client: the name of the application a hosted sign-in is for, recorded on that sign-in
internal/access/auth/queries.sql#DeleteTrustedDevicesForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/auth/queries.sql#DenyBackchannelRequestsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/auth/queries.sql#DenyDeviceAuthorizationsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/auth/queries.sql#EndLoginSession  secret-lookup: login session found by its cookie hash
internal/access/auth/queries.sql#ExpireAuthorizationCodesForLoginSession  session-scoped: the login session being ended
internal/access/auth/queries.sql#GetClientOrganization  global-client: client_id is unique platform-wide
internal/access/auth/queries.sql#GetLoginSession  secret-lookup: session found by its cookie token hash; reads its own account's status
internal/access/auth/queries.sql#IsSessionLiveForUser  session-scoped: the caller's own session and user
internal/access/auth/queries.sql#IsSessionOfUser  session-scoped: the caller's own session and user
internal/access/auth/queries.sql#LockUserForSessionRevocation  parent-scoped: locks an account its callers already checked
internal/access/auth/queries.sql#PurgeEndedSessions  background-sweep: session cleanup job
internal/access/auth/queries.sql#PurgeExpiredTrustedDevices  background-sweep: session cleanup job
internal/access/auth/queries.sql#RevokeAllSessionsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/auth/queries.sql#RevokeAppGrantsForLoginSession  session-scoped: the login session being ended
internal/access/auth/queries.sql#RevokeAppGrantsForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/auth/queries.sql#RevokeOtherSessionsForUser  session-scoped: the caller's own other sessions
internal/access/auth/queries.sql#RevokeSessionById  session-scoped: the session of the refresh token in use
internal/access/auth/queries.sql#RevokeSessionForUser  session-scoped: only a session of the caller's own user
internal/access/auth/queries.sql#SessionEnd  session-scoped: the caller's own session and user
internal/access/auth/queries.sql#ExpireRecoveryLinksForUser  parent-scoped: EndAllSignIns callers check the user first; an account's links are its own in every organization
internal/access/auth/queries.sql#SpendAuthorizationCodesForUser  parent-scoped: EndAllSignIns callers check the user first
internal/access/auth/queries.sql#SupersedeSession  session-scoped: the caller's own session, replaced on organization switch
internal/access/auth/queries.sql#TouchSession  session-scoped: the session of the verified access token
internal/access/auth/queries.sql#UpdateSessionLastSeen  session-scoped: the session of the refresh token in use
internal/access/authorization/accessrequest/queries.sql#EndingAccess  background-sweep: the access-request sweep takes back ended grants in every organization
internal/access/authorization/accessrequest/queries.sql#LapsePendingAccessRequests  background-sweep: the access-request sweep lapses unanswered requests in every organization
internal/access/authorization/rbac/queries.sql#GrantBuiltinRolePermissions  background-sweep: at boot, gives every organization's built-in roles the permissions their definitions cover
internal/access/authorization/rbac/queries.sql#GetRoleOrganization  parent-scoped: scopedRole compares the role's organization to httpx.RequireOrganization
internal/access/mfa/queries.sql#ResetLivePushPairings  parent-scoped: ResetForUser's caller checks the user's home organization first
internal/access/mfa/queries.sql#ResetTrustedDevices  parent-scoped: ResetForUser's caller checks the user's home organization first
internal/access/mfa/queries.sql#PurgeExpiredPushPairings  background-sweep: cleanup job for expired codes
internal/access/mfa/queries.sql#ClaimablePushPairing  secret-lookup: pairing found by its code hash
internal/access/mfa/queries.sql#UsePushPairing  secret-lookup: the pairing ClaimablePushPairing found by its code hash
internal/access/mfa/queries.sql#RecentPushPairings  session-scoped: the caller's own pairing codes
internal/access/mfa/queries.sql#ExpireLivePushPairings  session-scoped: the caller's own pairing codes
internal/access/mfa/queries.sql#GetPushPairing  session-scoped: the caller's own pairing codes
internal/access/mfa/queries.sql#WithdrawPushPairing  session-scoped: the caller's own pairing codes
internal/access/mfa/queries.sql#RecordStepUp  session-scoped: the caller's own session and user
internal/access/passkey/queries.sql#GetUserForWebAuthn  pre-organization: the caller's own account, or the one a passkey sign-in asserts
internal/access/passkey/queries.sql#GetUserIDByEmail  pre-organization: passkey sign-in finds the account by email
internal/access/recovery/queries.sql#ExpireMagicLinks  pre-organization: a new sign-in link ends the earlier ones to the same account's address
internal/access/recovery/queries.sql#GetMagicLinkAccount  pre-organization: magic-link sign-in finds the account by email
internal/access/recovery/queries.sql#GetMagicLinkByToken  secret-lookup: link found by its token hash
internal/access/recovery/queries.sql#GetResetAccount  secret-lookup: account named by the reset token
internal/access/recovery/queries.sql#MarkMagicLinkUsed  secret-lookup: link found by its token hash
internal/access/recovery/queries.sql#RevokeUserSessions  pending-review: unused query; delete it or add an organization condition
internal/access/recovery/queries.sql#VerifyEmailByLink  secret-lookup: account named by the reset or sign-in link
internal/access/recovery/queries.sql#FindResetAccount  pre-organization: password reset finds the account by email
internal/access/threat/risk/queries.sql#PurgeSignInHistory  background-sweep: retention job

internal/developer/apikey/queries.sql#TouchAPIKeyLastUsed  secret-lookup: the key just verified by its secret
internal/developer/credentials/tokenvault/queries.sql#DeleteConnectState  secret-lookup: single-use random OAuth state
internal/developer/credentials/vc/queries.sql#GetCredentialRevocation  parent-scoped: ID of a credential whose signature was just verified
internal/developer/webhook/queries.sql#ClaimDueDeliveries  background-sweep: delivery worker for every organization

internal/federation/adminportal/queries.sql#GetAdminPortalSessionByHash  secret-lookup: session found by its token hash
internal/federation/adminportal/queries.sql#LockAdminPortalLinkByHash  secret-lookup: link found by its token hash
internal/federation/identitylink/queries.sql#AddressVerified  pre-organization: federated sign-in checks the account it found
internal/federation/identitylink/queries.sql#MarkAddressVerified  pre-organization: federated sign-in marks the home account it just adopted
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
internal/federation/oidc/queries.sql#GetClientPostLogoutURIs  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetClientRedirectInfo  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetClientOrganizationAndScopes  global-client: client_id is unique platform-wide
internal/federation/oidc/queries.sql#GetDeviceByUserCode  secret-lookup: request found by its user code
internal/federation/oidc/queries.sql#GetRefreshTokenForIntrospect  secret-lookup: token row found by its hash, then bound to the calling client
internal/federation/oidc/queries.sql#GetUserinfo  session-scoped: account named by the verified access token
internal/federation/oidc/queries.sql#ListAllWebOrigins  platform-wide: the CORS allow-list of every application's web origins, read before a request names its application; no other column
internal/federation/oidc/queries.sql#ListPendingCIBA  session-scoped: the caller's own pending requests
internal/federation/oidc/queries.sql#CIBARequestOrganization  session-scoped: the caller's own request, found by its id and their user id
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
internal/federation/oidc/queries.sql#RevokeRefreshTokenChain  global-client: client_id belongs to one organization
internal/federation/oidc/queries.sql#RevokeRefreshTokenGrant  secret-lookup: by the authenticated client and its refresh token hash
internal/federation/oidc/queries.sql#SessionClients  session-scoped: clients of the login session being ended
internal/federation/oidc/queries.sql#TouchCIBAPollTime  secret-lookup: request found by its auth_req_id hash
internal/federation/oidc/queries.sql#TouchDevicePollTime  secret-lookup: request found by its device code hash
internal/federation/oauthstate/queries.sql#TakeState  secret-lookup: state found by its hash
internal/federation/oidcsso/queries.sql#GetOidcConnectionForSignIn  pre-organization: public sign-in endpoints; the connection in the path names the organization
internal/federation/provision/queries.sql#AccountByEmail  pre-organization: federated sign-in finds the account by email
internal/federation/saml/queries.sql#GetSamlConnectionByID  pre-organization: public SSO endpoints; the connection in the path names the organization
internal/federation/saml/queries.sql#GetUserForIdP  session-scoped: the IdP session's user; its organization is compared to the SP's
internal/federation/saml/queries.sql#ListSamlMetadataDue  background-sweep: the metadata refresh job finds every organization's due connections
internal/federation/saml/queries.sql#SamlAllowsIdPInitiated  parent-scoped: connection ID from a read that checked it
internal/federation/saml/queries.sql#TouchSamlLastLogin  parent-scoped: connection row read for this sign-in
internal/federation/saml/queries.sql#TouchSamlSPLastLogin  parent-scoped: service provider row read for this sign-in
internal/federation/scim/queries.sql#TagProvisionedUser  parent-scoped: account created for the organization in the same transaction

internal/federation/social/queries.sql#AccountAddressVerified  pre-organization: social sign-in checks the account it found
internal/federation/social/queries.sql#AccountByEmail  pre-organization: platform sign-in finds the account by email
internal/federation/social/queries.sql#AccountEmail  pre-organization: social sign-in reads the address of the account it found
internal/federation/social/queries.sql#AdoptAccountAvatar  pre-organization: platform sign-in fills in the picture of the account it found
internal/federation/social/queries.sql#InsertPlatformAccount  pre-organization: platform sign-up creates an account with no organization
internal/identity/domainverify/queries.sql#EmailDomainManager  platform-wide: a domain is verified by one organization; callers compare it with their own
internal/identity/invite/queries.sql#ActivateInvitedAccount  parent-scoped: account created for the invite in the same transaction
internal/identity/invite/queries.sql#DeclineInviteForEmail  session-scoped: only invites to the caller's verified email
internal/identity/invite/queries.sql#FindUserIDByEmail  pre-organization: email is unique across all accounts
internal/identity/invite/queries.sql#GetInboxEmail  session-scoped: the caller's own account
internal/identity/invite/queries.sql#GetInviteByIDForAccept  session-scoped: accepted only for the caller's verified email, or a new account's organization and email
internal/identity/invite/queries.sql#GetInviteForAccept  secret-lookup: invite found by its token hash
internal/identity/invite/queries.sql#GetUserEmailByID  session-scoped: the caller's own account
internal/identity/invite/queries.sql#InviteSenderByID  session-scoped: read for the same acceptance as GetInviteByIDForAccept, before its transaction
internal/identity/invite/queries.sql#InviteSenderByToken  secret-lookup: invite found by its token hash
internal/identity/invite/queries.sql#MarkInviteAccepted  parent-scoped: invite read under lock just before
internal/identity/invite/queries.sql#MarkInviteExpired  parent-scoped: invite read under lock just before
internal/identity/organization/queries.sql#IsEmailVerified  session-scoped: the caller's own account
internal/identity/user/queries.sql#GetUserByEmailGlobal  pre-organization: password sign-in finds the account by email
internal/identity/user/queries.sql#GetUserByID  parent-scoped: callers pass their own, a signing-in or an organization-checked account
internal/identity/user/queries.sql#LockAccount  parent-scoped: callers pass their own or an organization-checked account
internal/identity/user/queries.sql#MarkEmailVerified  pending-review: unused query; delete it or add an organization condition
internal/identity/user/queries.sql#PurgeUser  parent-scoped: the handler checks the user's home organization first
internal/identity/user/queries.sql#RestoreUser  parent-scoped: the handler checks the user's home organization first
internal/identity/user/queries.sql#SetUserMfaRequired  parent-scoped: the handler checks the user's home organization first
internal/identity/user/queries.sql#SoftDeleteUser  parent-scoped: SCIM checks the user belongs to the organization first
internal/identity/user/queries.sql#SoftDeleteUserBy  parent-scoped: the handler checks the user's home organization first
internal/identity/user/repository.go#Repository.update  parent-scoped: callers pass their own or an organization-checked account
internal/identity/verification/queries.sql#EmailTakenByOther  session-scoped: the caller's email change; email is unique platform-wide
internal/identity/verification/queries.sql#ExpireRecoveryLinksForUser  session-scoped: the caller's own links, ended as their address changes
internal/identity/verification/queries.sql#GetUserEmail  session-scoped: the caller's own account
internal/identity/verification/queries.sql#GetUserPhone  session-scoped: the caller's own account
internal/identity/verification/queries.sql#LockAccountForCodeSend  session-scoped: the caller's own account, held while a code is counted and stored
internal/identity/verification/queries.sql#MarkUserEmailVerified  session-scoped: the caller's own account
internal/identity/verification/queries.sql#SetUserVerifiedPhone  session-scoped: the caller's own account
internal/identity/verification/queries.sql#UpdateUserEmail  session-scoped: the caller's own account

internal/operations/audit/anomaly/queries.sql#ListUnscoredAuditEvents  background-sweep: anomaly scoring job
internal/operations/audit/anomaly/queries.sql#LockAuditEventForScoring  background-sweep: anomaly scoring job
internal/operations/audit/anomaly/queries.sql#MarkAuditEventScored  background-sweep: anomaly scoring job
internal/operations/audit/queries.sql#ListAuditChainCheckpoints  background-sweep: audit chain verification job, every chain's checkpoint
internal/operations/billing/queries.sql#ClaimInvoiceEmails  background-sweep: the invoice-email job sends every organization's newly issued invoices to the address each was billed to
internal/operations/billing/queries.sql#ClaimSignupCheckout  pre-organization: checkout named by a signature-verified payment webhook or callback; completing it creates the organization
internal/operations/billing/queries.sql#CompleteCheckout  parent-scoped: checkout named by a signature-verified payment webhook or callback
internal/operations/billing/queries.sql#DueSubscriptions  background-sweep: the period-end job finds every organization whose trial or period has ended
internal/operations/billing/queries.sql#FailSignupCheckout  pre-organization: the sign-up checkout inserted just before
internal/operations/billing/queries.sql#InsertSignupCheckout  pre-organization: sign-up checkout runs before the organization exists
internal/operations/billing/queries.sql#InvoiceOrganization  platform-wide: the operator's mark-invoice-paid command finds which organization an invoice belongs to, then settles it scoped to that one
internal/operations/billing/queries.sql#ReopenSignupCheckout  pre-organization: the sign-up checkout claimed just before, returned for a retry
internal/operations/billing/queries.sql#SetSignupCheckoutOrganization  pre-organization: records the organization the claimed sign-up checkout just created
internal/operations/billing/queries.sql#SetSignupCheckoutProviderRef  pre-organization: the sign-up checkout inserted just before
internal/operations/billing/queries.sql#UpdateCheckoutFailed  parent-scoped: checkout inserted for the organization just before
internal/operations/billing/queries.sql#UpdateCheckoutProviderRef  parent-scoped: checkout inserted for the organization just before
internal/operations/email/queries.sql#GetVerifiedEmail  session-scoped: sends to the caller's own verified email
internal/operations/gdpr/queries.sql#CompleteExportRequest  background-sweep: export worker holding the request lease
internal/operations/gdpr/queries.sql#CompletePurgeRequest  background-sweep: purge worker holding the request lease
internal/operations/gdpr/queries.sql#DropExportPayloads  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseAIConversations  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseAPIKeys  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseActorBaseline  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseAuthorizationCodes  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseBackchannelRequests  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseBreakGlassMemberships  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseDeviceCodes  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseDirectoryAlerts  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseDirectoryProfiles  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseExternalIdentities  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseGroupMemberships  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseLoginCodes  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseLoginContextHistory  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseMFALoginChallenges  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseMFAPushPairings  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseMagicLinksTo  parent-scoped: the address of the account being erased (see PurgeUserPII), in every organization
internal/operations/gdpr/queries.sql#EraseNotifications  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseOAuthLinkStates  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseRefreshTokens  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseRoleAssignments  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseSAMLAppAssignments  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseSAMLPersistentIDs  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseSessions  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseSpentInvitesTo  parent-scoped: the address of the account being erased (see PurgeUserPII), in every organization
internal/operations/gdpr/queries.sql#EraseTokenVaultConnectStates  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseTokenVaultGrants  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#EraseTrustedDevices  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/gdpr/queries.sql#ExpireReadyExports  background-sweep: export retention job
internal/operations/gdpr/queries.sql#GetOwnProfileForExport  session-scoped: the caller's own data export
internal/operations/gdpr/queries.sql#LeaseDuePurgeRequests  background-sweep: purge worker claiming due requests
internal/operations/gdpr/queries.sql#LeasePendingExportRequests  background-sweep: export worker claiming pending requests
internal/operations/gdpr/queries.sql#ListOwnSessionsForExport  session-scoped: the caller's own data export
internal/operations/gdpr/queries.sql#LockAccountHome  background-sweep: purge worker reads the home of the account its leased request names
internal/operations/gdpr/queries.sql#LockLeasedPurgeRequest  background-sweep: purge worker holding the request lease
internal/operations/gdpr/queries.sql#PurgeUserPII  parent-scoped: the caller erasing their own account, or one the erasure worker checked against its request under lock
internal/operations/gdpr/queries.sql#QuarantinePurgeRequest  background-sweep: purge worker holding the request lease
internal/operations/gdpr/queries.sql#RevokeIssuedCredentials  parent-scoped: the account being erased (see PurgeUserPII), everywhere it left data
internal/operations/notification/queries.sql#CountUnreadNotifications  session-scoped: the caller's own inbox; notifications belong to the account
internal/operations/notification/queries.sql#ListNotifications  session-scoped: the caller's own inbox; notifications belong to the account
internal/operations/notification/queries.sql#MarkAllNotificationsRead  session-scoped: the caller's own inbox; notifications belong to the account
internal/operations/qeetai/queries.sql#ListConversationRetention  background-sweep: the retention job finds every organization that keeps its Qeet AI conversations for a set time, then deletes each one's scoped to it
internal/operations/retention/queries.sql#ListEnabledRetentionPolicies  background-sweep: retention job
internal/operations/retention/queries.sql#SweepAccessDecisions  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepApplicationGrants  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepAuditAnomalies  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepAuthorizationCodes  background-sweep: retention job for every organization's spent sign-in state
internal/operations/retention/queries.sql#SweepBackchannelRequests  background-sweep: retention job for every organization's spent sign-in state
internal/operations/retention/queries.sql#SweepBotDetections  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepConnectedAccountStates  background-sweep: retention job for every organization's spent sign-in state
internal/operations/retention/queries.sql#SweepDeviceCodes  background-sweep: retention job for every organization's spent sign-in state
internal/operations/retention/queries.sql#SweepDirectorySyncEvents  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepFederatedSignInCodes  background-sweep: retention job for every organization's spent sign-in state
internal/operations/retention/queries.sql#SweepFederatedSignInStates  background-sweep: retention job for every organization's spent sign-in state
internal/operations/retention/queries.sql#SweepInvitations  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepLogoutDeliveries  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepMonthlyActiveUsers  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepNotifications  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepSecondFactorSignIns  background-sweep: retention job for every organization's spent sign-in state
internal/operations/retention/queries.sql#SweepSecurityEvents  background-sweep: retention job for every organization's old records
internal/operations/retention/queries.sql#SweepSignInLinks  background-sweep: retention job for every organization's spent sign-in state
internal/operations/siem/queries.sql#AdvanceLogSinkCursor  background-sweep: log forwarding job
internal/operations/siem/queries.sql#ClaimLogSink  background-sweep: log forwarding job, by sink id
internal/operations/siem/queries.sql#ListEnabledLogSinks  background-sweep: log forwarding job
internal/operations/siem/queries.sql#ReleaseLogSink  background-sweep: log forwarding job, by sink id
internal/operations/siem/queries.sql#SetLogSinkError  background-sweep: log forwarding job

internal/platform/cache/ratelimit/organization.go#OrganizationLimiter.GetAll  pending-review: unused method; lists every organization's overrides
internal/platform/cache/ratelimit/organization.go#OrganizationLimiter.LoadOverrides  background-sweep: startup load of every organization's override into the limiter
internal/platform/events/sessionsignal/sessionsignal.go#EndUserSessions  parent-scoped: callers check the user's home organization first, or erase the account
internal/platform/messaging/delivery/queries.sql#ActiveSuppression  platform-wide: an address's suppression stops every organization's mail; only the causing organization sees its detail
internal/platform/messaging/delivery/queries.sql#DeleteMessagesBefore  background-sweep: retention job
internal/platform/messaging/delivery/queries.sql#MessageByProviderID  parent-scoped: message named by a signature-verified SES notification
internal/platform/messaging/delivery/queries.sql#SetMessageStatus  parent-scoped: message found by its provider message ID just before
`
