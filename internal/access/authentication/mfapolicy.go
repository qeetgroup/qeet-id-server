package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// MFA enforcement at sign-in: an organisation's mfa_enforcement (optional,
// required or admin_only) or an account's mfa_required decides who must meet a
// second factor. An account that must but holds none sets one up first; existing
// members may postpone setup during the organisation's grace period.

// Why a sign-in is challenged.
const (
	mfaReasonEnrolled       = "enrolled"
	mfaReasonTenantRequired = "tenant_required"
	mfaReasonAdminRequired  = "admin_required"
	mfaReasonUserRequired   = "user_required"
)

// mfaRequirement is whether, and why, an account must use a second factor to
// sign in.
type mfaRequirement struct {
	// reason is why the account must; "" when it need not.
	reason string
	// graceUntil is set while the organisation's grace period lets the
	// account put the setup off.
	graceUntil *time.Time
}

// decideMFARequirement applies the rules above to what MFARequirement read.
func decideMFARequirement(row dbgen.MFARequirementRow, now time.Time) mfaRequirement {
	if row.MfaRequired {
		return mfaRequirement{reason: mfaReasonUserRequired}
	}
	var req mfaRequirement
	switch {
	case row.Enforcement == "required":
		req.reason = mfaReasonTenantRequired
	case row.Enforcement == "admin_only" && row.IsAdmin:
		req.reason = mfaReasonAdminRequired
	default:
		return req
	}
	if row.GraceDays > 0 && row.MfaEnforcedSince.Valid && row.JoinedAt.Before(row.MfaEnforcedSince.Time) {
		until := row.MfaEnforcedSince.Time.Add(time.Duration(row.GraceDays) * 24 * time.Hour)
		if now.Before(until) {
			req.graceUntil = &until
		}
	}
	return req
}

// mfaRequirementFor reads, through q, whether the account must use a second
// factor to sign in to tenantID (uuid.Nil: only the account's own flag applies).
func mfaRequirementFor(ctx context.Context, q *dbgen.Queries, userID, tenantID uuid.UUID) (mfaRequirement, error) {
	row, err := q.MFARequirement(ctx, dbgen.MFARequirementParams{UserID: userID, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return mfaRequirement{}, nil
	}
	if err != nil {
		return mfaRequirement{}, err
	}
	return decideMFARequirement(row, time.Now()), nil
}

// How a session's sign-in met a second factor. Every session records it, so
// entering another organisation can be checked against that organisation's
// requirement (see tenantFactorShortfall).
const (
	secondFactorMFA           = "mfa"
	secondFactorPasskey       = "passkey"
	secondFactorTrustedDevice = "trusted_device"
	secondFactorStepUp        = "step_up"
)

// secondFactorOfMethod is the second factor a session opened by a sign-in of
// this method met ("" for none): a met challenge ("<first factor>_mfa") or a
// passkey.
func secondFactorOfMethod(method string) string {
	switch {
	case strings.HasSuffix(method, "_mfa"):
		return secondFactorMFA
	case method == "passkey":
		return secondFactorPasskey
	}
	return ""
}

// stricterRequirement is the requirement of two organisations an account
// meets at once: either one's, and a grace period only while both allow one,
// ending at the earlier.
func stricterRequirement(a, b mfaRequirement) mfaRequirement {
	switch {
	case a.reason == "":
		return b
	case b.reason == "":
		return a
	}
	out := mfaRequirement{reason: a.reason}
	if a.graceUntil != nil && b.graceUntil != nil {
		out.graceUntil = a.graceUntil
		if b.graceUntil.Before(*a.graceUntil) {
			out.graceUntil = b.graceUntil
		}
	}
	return out
}

// tenantFactorShortfall reports what stops a session or code being issued for
// tenantID to userID, whose sign-in met secondFactor ("" for none): nil,
// ErrMFAEnrollmentRequired when a factor must be set up first, or
// ErrStepUpRequired when the account holds one this sign-in didn't use.
func (s *Service) tenantFactorShortfall(ctx context.Context, userID, tenantID uuid.UUID, secondFactor string) error {
	if s.mfa == nil || tenantID == uuid.Nil || secondFactor != "" {
		return nil
	}
	req, err := mfaRequirementFor(ctx, s.q, userID, tenantID)
	if err != nil || req.reason == "" {
		return err
	}
	factors, err := s.mfa.LoginFactors(ctx, userID)
	if err != nil {
		return err
	}
	meta := map[string]any{"reason": req.reason, "tenant_id": tenantID}
	if len(factors) == 0 {
		if req.graceUntil != nil {
			return nil
		}
		return errs.ErrMFAEnrollmentRequired.WithMetadata(meta)
	}
	return errs.ErrStepUpRequired.WithMetadata(meta)
}

// mfaGate is what decides a password sign-in's second factor: the factors the
// account holds and whether it must use one.
type mfaGate struct {
	factors []LoginFactor
	req     mfaRequirement
}

// challenged reports whether the sign-in stops at a challenge.
func (g mfaGate) challenged() bool { return len(g.factors) > 0 || g.req.reason != "" }

// enrollment reports whether the challenge is met by setting up a factor.
func (g mfaGate) enrollment() bool { return len(g.factors) == 0 && g.req.reason != "" }

// skippedFactor is the second factor recorded for a sign-in that went on to a
// session without a challenge: a gate that would have challenged was passed by
// a remembered device (see nextSignInStep), which stands in for the factor;
// otherwise none was met.
func (g mfaGate) skippedFactor() string {
	if g.challenged() && !g.enrollment() {
		return secondFactorTrustedDevice
	}
	return ""
}

// reason is why the sign-in is challenged, as audited.
func (g mfaGate) reason() string {
	if g.req.reason != "" {
		return g.req.reason
	}
	return mfaReasonEnrolled
}

// mfaGate reads the account's factors and requirement. With no MFA service
// wired nothing is challenged.
func (s *Service) mfaGate(ctx context.Context, userID, tenantID uuid.UUID) (mfaGate, error) {
	return s.mfaGateFor(ctx, userID, tenantID, uuid.Nil)
}

// mfaGateFor is mfaGate for a sign-in that also enters alsoTenant (uuid.Nil:
// none) — the organisation of the application a hosted sign-in serves — whose
// requirement applies as well as the home organisation's.
func (s *Service) mfaGateFor(ctx context.Context, userID, tenantID, alsoTenant uuid.UUID) (mfaGate, error) {
	if s.mfa == nil {
		return mfaGate{}, nil
	}
	factors, err := s.mfa.LoginFactors(ctx, userID)
	if err != nil {
		return mfaGate{}, err
	}
	req, err := mfaRequirementFor(ctx, s.q, userID, tenantID)
	if err != nil {
		return mfaGate{}, err
	}
	if alsoTenant != uuid.Nil && alsoTenant != tenantID {
		also, err := mfaRequirementFor(ctx, s.q, userID, alsoTenant)
		if err != nil {
			return mfaGate{}, err
		}
		req = stricterRequirement(req, also)
	}
	return mfaGate{factors: factors, req: req}, nil
}

// MFAEnrollment is an authenticator app being set up for an enrolment
// challenge: the secret to enter, or the otpauth:// URL to scan.
type MFAEnrollment struct {
	Secret          string `json:"secret"`
	ProvisioningURL string `json:"provisioning_url"`
}

// StartMFAEnrollment starts an authenticator app for an enrolment challenge.
// Starting again replaces the app not yet confirmed. Refused for a challenge
// that is not an enrolment one, and as expired once the account holds a
// factor (sign in again to be challenged for it).
func (s *Service) StartMFAEnrollment(ctx context.Context, mfaToken, ip, ua string) (MFAEnrollment, error) {
	var out MFAEnrollment
	err := s.withMFAChallenge(ctx, mfaToken, func(tx pgx.Tx, id uuid.UUID, c pendingMFAChallenge) error {
		if !c.enrollment {
			return errs.ErrBadRequest.WithDetail("This sign-in is not setting up a second factor.")
		}
		if err := s.stillWithoutFactor(ctx, tx, c.userID); err != nil {
			return err
		}
		u, err := s.users.GetTx(ctx, tx, c.userID)
		if err != nil {
			return err
		}
		if out.Secret, out.ProvisioningURL, err = s.mfa.StartLoginEnrollment(ctx, tx, c.userID, u.Email); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.mfa_login_challenges SET enrollment_started = TRUE WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{
			TenantID:     c.tenantID,
			ActorUserID:  &c.userID,
			ActorType:    "user",
			Action:       "mfa.totp_enroll_started",
			ResourceType: "user",
			ResourceID:   &c.userID,
			IP:           ip,
			UserAgent:    ua,
			Metadata:     map[string]any{"via": "sign_in"},
		})
	})
	return out, err
}

// stillWithoutFactor refuses, as an expired challenge, an enrolment challenge
// for an account that has gained a factor since it was raised: setting up
// another, or skipping, must not get round the one it now holds. Read through
// the challenge transaction tx.
func (s *Service) stillWithoutFactor(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	factors, err := s.mfa.LoginFactorsTx(ctx, tx, userID)
	if err != nil {
		return err
	}
	if len(factors) > 0 {
		return errs.ErrAuthMFAChallengeExpired
	}
	return nil
}

// mayDeferEnrollment refuses with ErrMFAEnrollmentRequired a skipped
// enrolment challenge once the account must set up a factor now — the grace
// period has ended, or never applied. If the requirement has been lifted
// since, skipping is allowed. Read through the challenge transaction tx.
func (s *Service) mayDeferEnrollment(ctx context.Context, tx pgx.Tx, userID, tenantID uuid.UUID) (*time.Time, error) {
	if err := s.stillWithoutFactor(ctx, tx, userID); err != nil {
		return nil, err
	}
	req, err := mfaRequirementFor(ctx, s.q.WithTx(tx), userID, tenantID)
	if err != nil {
		return nil, err
	}
	if req.reason != "" && req.graceUntil == nil {
		return nil, errs.ErrMFAEnrollmentRequired
	}
	return req.graceUntil, nil
}
