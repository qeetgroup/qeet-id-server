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

// Enforcing the MFA an organisation requires (security policy
// mfa_enforcement) or an administrator requires of one account
// (users.mfa_required) at password sign-in:
//
//   - optional: only an account holding a second factor is challenged.
//   - required: every account of the organisation must meet a challenge.
//   - admin_only: administrators must — accounts holding a role, directly or
//     through a group, that grants any write permission.
//   - an account marked as requiring MFA must, whatever its organisation sets.
//
// An account that must and holds a factor is challenged as usual. One that
// holds none gets an enrolment challenge instead of a session: it sets up an
// authenticator app (StartMFAEnrollment) and the code that confirms the app
// meets the challenge, so no session is issued before a factor exists.
//
// Grace period: for mfa_grace_days after the organisation turns its
// requirement on, the members it already had may put the setup off — they
// still get the enrolment challenge, and may skip it (MFAProof.Skip) until
// the grace period ends. Accounts created later, and accounts marked
// individually, have none.
//
// Every challenge is audited as auth.mfa_challenged with its reason, so one
// raised by policy is told apart from one raised because the person chose to
// set up a factor.

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

// mfaRequirementFor reads whether the account must use a second factor to sign
// in to tenantID (uuid.Nil: only the account's own flag applies).
func (s *Service) mfaRequirementFor(ctx context.Context, userID, tenantID uuid.UUID) (mfaRequirement, error) {
	row, err := s.q.MFARequirement(ctx, dbgen.MFARequirementParams{UserID: userID, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return mfaRequirement{}, nil
	}
	if err != nil {
		return mfaRequirement{}, err
	}
	return decideMFARequirement(row, time.Now()), nil
}

// The requirement belongs to the organisation being entered, not only to the
// one the account calls home (QTID-800). Signing in reads the home
// organisation's; everything that issues a session or a code for another
// organisation — switching into it, accepting its invitation, signing in to one
// of its applications, approving a device for one — asks tenantFactorShortfall
// first. For that every session records whether, and how, its sign-in met a
// second factor (auth.sessions and auth.login_sessions second_factor,
// migration 0149).
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

// tenantFactorShortfall is what stops a session or a code being issued for
// tenantID to userID, whose sign-in met secondFactor ("": none): nil when
// nothing does — the organisation doesn't require a factor of the account, the
// sign-in met one, or the account holds none and the organisation's grace
// period still lets it put the setup off. Otherwise ErrMFAEnrollmentRequired
// when the account must set a factor up first, or ErrStepUpRequired when it
// holds one this sign-in didn't use.
func (s *Service) tenantFactorShortfall(ctx context.Context, userID, tenantID uuid.UUID, secondFactor string) error {
	if s.mfa == nil || tenantID == uuid.Nil || secondFactor != "" {
		return nil
	}
	req, err := s.mfaRequirementFor(ctx, userID, tenantID)
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
	req, err := s.mfaRequirementFor(ctx, userID, tenantID)
	if err != nil {
		return mfaGate{}, err
	}
	if alsoTenant != uuid.Nil && alsoTenant != tenantID {
		also, err := s.mfaRequirementFor(ctx, userID, alsoTenant)
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
		if err := s.stillWithoutFactor(ctx, c.userID); err != nil {
			return err
		}
		u, err := s.users.Get(ctx, c.userID)
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
// another, or skipping, must not get round the one it now holds.
func (s *Service) stillWithoutFactor(ctx context.Context, userID uuid.UUID) error {
	factors, err := s.mfa.LoginFactors(ctx, userID)
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
// since, skipping is allowed.
func (s *Service) mayDeferEnrollment(ctx context.Context, userID, tenantID uuid.UUID) (*time.Time, error) {
	if err := s.stillWithoutFactor(ctx, userID); err != nil {
		return nil, err
	}
	req, err := s.mfaRequirementFor(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if req.reason != "" && req.graceUntil == nil {
		return nil, errs.ErrMFAEnrollmentRequired
	}
	return req.graceUntil, nil
}
