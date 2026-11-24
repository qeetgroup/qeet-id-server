package gdpr

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// accountData deletes what an erased account leaves outside its user row and the audit trail:
// credentials, factors, sign-ins, devices, linked accounts, grants, vault tokens, memberships,
// directory profiles, inbox, behaviour baseline and AI conversations; exports lose their payloads and
// issued credentials are revoked. Each statement takes the account and runs in this order.
var accountData = []func(*dbgen.Queries, context.Context, uuid.UUID) error{
	(*dbgen.Queries).ErasePasskeyCredentials,
	(*dbgen.Queries).EraseWebAuthnSessions,
	(*dbgen.Queries).EraseMFAOTPFactors,
	(*dbgen.Queries).EraseMFAPushPairings,
	(*dbgen.Queries).EraseMFAPushChallenges,
	(*dbgen.Queries).EraseMFAPushDevices,
	(*dbgen.Queries).EraseMFAVerifications,
	(*dbgen.Queries).EraseMFALoginChallenges,
	(*dbgen.Queries).EraseMFAAttemptBudgets,
	(*dbgen.Queries).EraseMFAFailureStreaks,
	(*dbgen.Queries).EraseTrustedDevices,
	(*dbgen.Queries).EraseSessions,
	(*dbgen.Queries).EraseLoginSessions,
	(*dbgen.Queries).EraseLoginContextHistory,
	(*dbgen.Queries).EraseRefreshTokens,
	(*dbgen.Queries).EraseConsents,
	(*dbgen.Queries).EraseConsentRequests,
	(*dbgen.Queries).EraseAuthorizationCodes,
	(*dbgen.Queries).EraseDeviceCodes,
	(*dbgen.Queries).EraseBackchannelRequests,
	(*dbgen.Queries).EraseLoginCodes,
	(*dbgen.Queries).ErasePlatformSocialLinkCodes,
	(*dbgen.Queries).EraseOAuthLinkStates,
	(*dbgen.Queries).ErasePlatformSocialIdentities,
	(*dbgen.Queries).EraseExternalIdentities,
	(*dbgen.Queries).ErasePasswordCredentials,
	(*dbgen.Queries).ErasePasswordResets,
	(*dbgen.Queries).EraseMFATOTP,
	(*dbgen.Queries).EraseMFARecoveryCodes,
	(*dbgen.Queries).EraseEmailVerifications,
	(*dbgen.Queries).ErasePhoneVerifications,
	(*dbgen.Queries).EraseAPIKeys,
	(*dbgen.Queries).EraseNotifications,
	(*dbgen.Queries).EraseTokenVaultGrants,
	(*dbgen.Queries).EraseTokenVaultConnectStates,
	(*dbgen.Queries).EraseDirectoryProfiles,
	(*dbgen.Queries).EraseDirectoryAlerts,
	(*dbgen.Queries).EraseGroupMemberships,
	(*dbgen.Queries).EraseSAMLAppAssignments,
	(*dbgen.Queries).EraseSAMLPersistentIDs,
	(*dbgen.Queries).EraseBreakGlassMemberships,
	(*dbgen.Queries).EraseRoleAssignments,
	(*dbgen.Queries).EraseActorBaseline,
	(*dbgen.Queries).EraseAIConversations,
	(*dbgen.Queries).RevokeIssuedCredentials,
	(*dbgen.Queries).DropExportPayloads,
}

// addressData deletes what is kept by the account's address rather than its
// ID: sign-in links, failed sign-in counters, and invitations that were
// answered or have lapsed. Each statement takes the address, lowercased.
var addressData = []func(*dbgen.Queries, context.Context, string) error{
	(*dbgen.Queries).EraseMagicLinksTo,
	(*dbgen.Queries).EraseLoginAttemptsOf,
	(*dbgen.Queries).EraseNetworkLoginAttemptsOf,
	(*dbgen.Queries).EraseSourceFailuresOf,
	(*dbgen.Queries).EraseSpentInvitesTo,
}

// eraseAccountData deletes, in tx, the data of the account being erased that
// lies outside its user row; email is the account's address before
// redaction. The caller redacts the user row and keeps the audit trail.
func eraseAccountData(ctx context.Context, tx pgx.Tx, userID uuid.UUID, email string) error {
	q := dbgen.New(tx)
	for _, erase := range accountData {
		if err := erase(q, ctx, userID); err != nil {
			return err
		}
	}
	address := strings.ToLower(strings.TrimSpace(email))
	for _, erase := range addressData {
		if err := erase(q, ctx, address); err != nil {
			return err
		}
	}
	return nil
}

// endSessions ends every session of the account being erased and announces
// each one (reason deleted) in the erasure's transaction.
func (s *Service) endSessions(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	ended, err := sessionsignal.EndUserSessions(ctx, tx, userID)
	if err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonDeleted, ended...)
	return nil
}

// eraseAccount ends the account's sessions, redacts its user row and deletes
// the rest of its data (see accountData and addressData), in tx. The redacted
// user row and the audit trail are kept, so past events stay verifiable. The
// caller has checked that the account may be erased.
func (s *Service) eraseAccount(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	// Sessions first, announced before anything about the account is redacted.
	if err := s.endSessions(ctx, tx, userID); err != nil {
		return err
	}
	email, err := dbgen.New(tx).PurgeUserPII(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	return eraseAccountData(ctx, tx, userID, email)
}
