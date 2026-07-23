// Package mfa implements TOTP enrollment and verification plus a small
// set of recovery codes. Recovery codes are bcrypt-hashed; the user sees
// the plaintext list exactly once at generation.
//
// Mutating methods take a pgx.Tx so the caller (HTTP handler) can wrap
// the mutation plus its audit row in a single transaction.
package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer string // "qeet-id" — shown in the authenticator app
	sender notifier.Sender
}

func NewService(pool *pgxpool.Pool, issuer string, sender notifier.Sender) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer, sender: sender}
}

const otpTTL = 10 * time.Minute

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an MFA mutation and its audit row.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

type Enrollment struct {
	Secret          string `json:"secret"`
	ProvisioningURL string `json:"provisioning_url"`
}

func (s *Service) StartEnroll(ctx context.Context, tx pgx.Tx, userID uuid.UUID, account string) (*Enrollment, error) {
	secret, err := totp.NewSecret()
	if err != nil {
		return nil, err
	}
	if err := s.q.WithTx(tx).UpsertMFATOTP(ctx, dbgen.UpsertMFATOTPParams{
		UserID: userID,
		Secret: secret,
	}); err != nil {
		return nil, err
	}
	return &Enrollment{
		Secret:          secret,
		ProvisioningURL: totp.ProvisioningURL(secret, s.issuer, account),
	}, nil
}

func (s *Service) ConfirmEnroll(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) ([]string, error) {
	qtx := s.q.WithTx(tx)
	secret, err := qtx.GetMFATOTPSecret(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("enrollment not started")
	}
	if err != nil {
		return nil, err
	}
	if !totp.Verify(secret, code) {
		return nil, errs.ErrBadRequest.WithDetail("invalid totp code")
	}
	if err := qtx.ConfirmMFATOTP(ctx, userID); err != nil {
		return nil, err
	}
	// Completing enrollment is itself a successful factor verification (the user
	// just proved possession of the authenticator), so it refreshes the step-up
	// window — otherwise the very next sensitive action (regenerate recovery
	// codes, disable TOTP), which is RequireRecentMFA-gated, would 403 with no
	// way to satisfy it (QID-17).
	if err := s.RecordVerification(ctx, tx, userID, "totp"); err != nil {
		return nil, err
	}
	// Wipe old recovery codes, mint a fresh batch.
	return s.mintRecoveryCodes(ctx, tx, userID)
}

const recoveryCodeCount = 10

// mintRecoveryCodes replaces a user's recovery codes with a fresh batch and
// returns the plaintext exactly once; only the bcrypt hashes are persisted.
func (s *Service) mintRecoveryCodes(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]string, error) {
	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return nil, err
	}
	out := make([]string, recoveryCodeCount)
	for i := range out {
		c, err := codes.Numeric(10)
		if err != nil {
			return nil, err
		}
		hash, err := password.Hash(c)
		if err != nil {
			return nil, err
		}
		if err := qtx.InsertMFARecoveryCode(ctx, dbgen.InsertMFARecoveryCodeParams{
			UserID:   userID,
			CodeHash: hash,
		}); err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

// RecoveryStatus summarises a user's backup codes for the account UI.
type RecoveryStatus struct {
	Enrolled  bool `json:"enrolled"` // TOTP confirmed — recovery codes back a real factor
	Total     int  `json:"total"`
	Remaining int  `json:"remaining"`
}

func (s *Service) RecoveryStatus(ctx context.Context, userID uuid.UUID) (*RecoveryStatus, error) {
	var st RecoveryStatus
	ts, err := s.q.GetMFATOTPConfirmed(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	st.Enrolled = err == nil && ts.Valid
	stats, err := s.q.GetMFARecoveryCodeStats(ctx, userID)
	if err != nil {
		return nil, err
	}
	st.Total = int(stats.Total)
	st.Remaining = int(stats.Remaining)
	return &st, nil
}

// Regenerate issues a fresh set of recovery codes, invalidating the old set.
// Requires confirmed TOTP — recovery codes are a backup for an enrolled factor.
func (s *Service) Regenerate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]string, error) {
	ts, err := s.q.WithTx(tx).GetMFATOTPConfirmed(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("enable MFA before generating recovery codes")
	}
	if err != nil {
		return nil, err
	}
	if !ts.Valid {
		return nil, errs.ErrBadRequest.WithDetail("confirm MFA enrollment first")
	}
	return s.mintRecoveryCodes(ctx, tx, userID)
}

func (s *Service) Disable(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteMFATOTP(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return err
	}
	return nil
}

// VerifyResult tells the caller whether the supplied code matched a TOTP
// or a recovery code. The handler audits accordingly.
type VerifyResult struct {
	UsedRecoveryCode bool
	RecoveryCodeID   *uuid.UUID
}

// Verify accepts a TOTP code or a one-time recovery code. Recovery codes
// are consumed on use. The caller passes a tx so the consumption and any
// audit row commit together.
func (s *Service) Verify(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (*VerifyResult, error) {
	code = strings.TrimSpace(code)
	qtx := s.q.WithTx(tx)

	totpRow, err := qtx.GetMFATOTPFull(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("mfa not configured")
	}
	if err != nil {
		return nil, err
	}
	if !totpRow.ConfirmedAt.Valid {
		return nil, errs.ErrBadRequest.WithDetail("mfa enrollment not confirmed")
	}
	if totp.Verify(totpRow.Secret, code) {
		return &VerifyResult{}, nil
	}
	// Recovery code fallback.
	rcRows, err := qtx.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return nil, err
	}
	var matchedID *uuid.UUID
	for _, rc := range rcRows {
		if password.Verify(rc.CodeHash, code) {
			matched := rc.ID
			matchedID = &matched
		}
	}
	if matchedID == nil {
		return nil, errs.ErrUnauthorized.WithDetail("invalid mfa code")
	}
	if err := qtx.MarkRecoveryCodeUsed(ctx, *matchedID); err != nil {
		return nil, err
	}
	return &VerifyResult{UsedRecoveryCode: true, RecoveryCodeID: matchedID}, nil
}

// IsEnrolled reports whether the user has a second factor that can satisfy the
// login MFA step today: a confirmed TOTP factor (recovery codes back it). The
// auth package consults this (via the MFAEnroller interface) to decide whether
// to challenge for a second factor at login.
func (s *Service) IsEnrolled(ctx context.Context, userID uuid.UUID) (bool, error) {
	ts, err := s.q.GetMFATOTPConfirmed(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ts.Valid, nil
}

// VerifyForLogin verifies a TOTP or recovery code as the second step of login
// and records the verification (so a step-up window is open immediately after
// sign-in). Returns (false, nil) when the code is simply wrong/expired; a
// non-nil error indicates an infrastructure failure.
func (s *Service) VerifyForLogin(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	res, err := s.Verify(ctx, tx, userID, code)
	if err != nil {
		// A domain error (wrong/expired code, not-configured) means "not
		// verified" — surface it as a clean negative, not a 500.
		if errs.As(err) != nil {
			return false, nil
		}
		return false, err
	}
	method := "totp"
	if res.UsedRecoveryCode {
		method = "recovery_code"
	}
	if err := s.RecordVerification(ctx, tx, userID, method); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// ResetForUser clears every MFA factor for a user — TOTP, recovery codes, and
// email/SMS OTP factors (OTP codes cascade via FK). This is an admin
// account-recovery operation (a user locked out of their authenticator); the
// caller wraps it + an audit row in one transaction.
func (s *Service) ResetForUser(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	qtx := s.q.WithTx(tx)
	if err := qtx.DeleteMFATOTP(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteMFAOTPFactors(ctx, userID); err != nil {
		return err
	}
	return nil
}

// Email / SMS OTP factors

// OTPFactor is the account-facing view of a registered OTP channel. The
// destination is masked so the UI can show which factor without exposing the
// full address/number.
type OTPFactor struct {
	ID          uuid.UUID `json:"id"`
	Channel     string    `json:"channel"`
	Destination string    `json:"destination"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
}

func maskDestination(channel, dest string) string {
	if channel == "email" {
		at := strings.IndexByte(dest, '@')
		if at <= 1 {
			return dest
		}
		return dest[:1] + strings.Repeat("*", at-1) + dest[at:]
	}
	// phone: keep the last 3 digits.
	if len(dest) <= 3 {
		return dest
	}
	return strings.Repeat("*", len(dest)-3) + dest[len(dest)-3:]
}

// sendOTP generates a code for the factor, persists its hash, and dispatches
// the plaintext via the configured channel.
func (s *Service) sendOTP(ctx context.Context, factorID uuid.UUID, channel, destination string) error {
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	if err := s.q.InsertMFAOTPCode(ctx, dbgen.InsertMFAOTPCodeParams{
		FactorID:  factorID,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(otpTTL),
	}); err != nil {
		return err
	}
	return s.sender.Send(ctx, notifier.Message{
		Channel: channel,
		To:      destination,
		Subject: "Your verification code",
		Body:    fmt.Sprintf("Your %s sign-in code is %s. It expires in %s.", s.issuer, code, otpTTL),
	})
}

// EnrollOTPStart registers (or re-arms) a channel and sends a confirmation
// code. The factor is unverified until EnrollOTPConfirm succeeds.
func (s *Service) EnrollOTPStart(ctx context.Context, userID uuid.UUID, channel, destination string) (uuid.UUID, error) {
	channel = strings.ToLower(strings.TrimSpace(channel))
	destination = strings.TrimSpace(destination)
	if channel != "email" && channel != "sms" {
		return uuid.Nil, errs.ErrUnprocessable.WithDetail("channel must be email or sms")
	}
	if destination == "" {
		return uuid.Nil, errs.ErrUnprocessable.WithDetail("destination required")
	}
	factorID, err := s.q.UpsertMFAOTPFactor(ctx, dbgen.UpsertMFAOTPFactorParams{
		UserID:      userID,
		Channel:     channel,
		Destination: destination,
	})
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.sendOTP(ctx, factorID, channel, destination); err != nil {
		return uuid.Nil, err
	}
	return factorID, nil
}

// EnrollOTPConfirm verifies the code and marks the factor usable.
func (s *Service) EnrollOTPConfirm(ctx context.Context, tx pgx.Tx, userID, factorID uuid.UUID, code string) error {
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForConfirm(ctx, dbgen.GetOTPCodeForConfirmParams{
		ID:       factorID,
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrBadRequest.WithDetail("invalid or expired code")
	}
	if err != nil {
		return err
	}
	if err := qtx.MarkOTPCodeUsed(ctx, codeID); err != nil {
		return err
	}
	if err := qtx.MarkOTPFactorVerified(ctx, factorID); err != nil {
		return err
	}
	return nil
}

func (s *Service) ListOTPFactors(ctx context.Context, userID uuid.UUID) ([]OTPFactor, error) {
	rows, err := s.q.ListOTPFactors(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]OTPFactor, 0, len(rows))
	for _, m := range rows {
		out = append(out, OTPFactor{
			ID:          m.ID,
			Channel:     m.Channel,
			Destination: maskDestination(m.Channel, m.Destination),
			Verified:    m.VerifiedAt.Valid,
			CreatedAt:   m.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) DeleteOTPFactor(ctx context.Context, tx pgx.Tx, userID, factorID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteOTPFactor(ctx, dbgen.DeleteOTPFactorParams{
		ID:     factorID,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// ChallengeOTP sends a fresh code to a verified factor (login / step-up).
func (s *Service) ChallengeOTP(ctx context.Context, userID, factorID uuid.UUID) error {
	row, err := s.q.GetOTPFactorForChallenge(ctx, dbgen.GetOTPFactorForChallengeParams{
		ID:     factorID,
		UserID: userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if !row.VerifiedAt.Valid {
		return errs.ErrBadRequest.WithDetail("factor not confirmed")
	}
	return s.sendOTP(ctx, factorID, row.Channel, row.Destination)
}

// VerifyOTP consumes a code from any of the user's verified OTP factors.
func (s *Service) VerifyOTP(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (bool, error) {
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForVerify(ctx, dbgen.GetOTPCodeForVerifyParams{
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := qtx.MarkOTPCodeUsed(ctx, codeID); err != nil {
		return false, err
	}
	return true, nil
}

// Step-up MFA

// defaultStepUpWindow is how long a successful verification keeps a sensitive
// action unlocked. Five minutes balances friction against replay risk.
const defaultStepUpWindow = 5 * time.Minute

// RecordVerification UPSERTs the user's latest successful second-factor
// verification. method is one of "totp", "recovery_code", "otp", "webauthn".
// Callers that already hold a tx (so the verification commits atomically with
// the factor mutation) pass it in.
func (s *Service) RecordVerification(ctx context.Context, tx pgx.Tx, userID uuid.UUID, method string) error {
	return s.q.WithTx(tx).UpsertMFAVerification(ctx, dbgen.UpsertMFAVerificationParams{
		UserID: userID,
		Method: method,
	})
}

// recordVerification records a verification outside any caller transaction, for
// the WebAuthn route which has no surrounding tx.
func (s *Service) recordVerification(ctx context.Context, userID uuid.UUID, method string) error {
	return s.q.UpsertMFAVerification(ctx, dbgen.UpsertMFAVerificationParams{
		UserID: userID,
		Method: method,
	})
}

// RecentlyVerified reports whether the user completed a second-factor
// verification within window, and when. A missing row is a clean (false, nil).
func (s *Service) RecentlyVerified(ctx context.Context, userID uuid.UUID, window time.Duration) (bool, *time.Time, error) {
	verifiedAt, err := s.q.GetMFAVerification(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	fresh := time.Since(verifiedAt) <= window
	return fresh, &verifiedAt, nil
}

// RequireRecentMFA gates a handler behind a recent step-up verification. The
// principal must have completed any second factor within window; otherwise the
// request is refused with a 403 "step_up_required" so the client can prompt for
// re-verification before retrying.
func RequireRecentMFA(svc *Service, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := httpx.PrincipalFromCtx(r.Context())
			if p == nil || p.UserID == nil {
				httpx.WriteError(w, r, errs.ErrUnauthorized)
				return
			}
			ok, _, err := svc.RecentlyVerified(r.Context(), *p.UserID, window)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			if !ok {
				httpx.WriteError(w, r, errs.ErrStepUpRequired.WithDetail("recent multi-factor verification required"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WebAuthnVerifier asserts an already-authenticated user's existing passkey
// credentials as a second factor. It is satisfied by *passkey.Service; the
// interface lives here so package mfa can mount the routes without importing
// package passkey (which would create an import cycle — passkey already imports
// the lower-level platform packages mfa shares).
type WebAuthnVerifier interface {
	BeginMFA(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialAssertion, error)
	FinishMFA(ctx context.Context, userID, sessionID uuid.UUID, cred json.RawMessage) error
}

type Handler struct {
	Service *Service
	// WebAuthn, when set, exposes the user's registered passkeys as a second
	// factor (POST /mfa/webauthn/{challenge,verify}). Nil = feature disabled.
	WebAuthn WebAuthnVerifier
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/mfa/totp/enroll/start", h.startEnroll)
	r.Post("/mfa/totp/enroll/confirm", h.confirmEnroll)
	r.Post("/mfa/totp/verify", h.verify)
	r.Get("/mfa/recovery-codes", h.recoveryStatus)
	r.Get("/mfa/otp/factors", h.listOTPFactors)
	r.Post("/mfa/otp/factors", h.enrollOTPStart)
	r.Post("/mfa/otp/factors/{id}/confirm", h.enrollOTPConfirm)
	r.Post("/mfa/otp/factors/{id}/challenge", h.challengeOTP)
	r.Delete("/mfa/otp/factors/{id}", h.deleteOTPFactor)
	r.Post("/mfa/otp/verify", h.verifyOTP)

	// WebAuthn as a second factor: assert the user's existing passkeys.
	r.Post("/mfa/webauthn/challenge", h.webauthnChallenge)
	r.Post("/mfa/webauthn/verify", h.webauthnVerify)

	// Step-up status — lets a client decide whether to prompt before a
	// sensitive action.
	r.Get("/mfa/step-up/status", h.stepUpStatus)

	// Sensitive MFA actions require a recent step-up verification (any factor):
	// disabling MFA wholesale and regenerating recovery codes both invalidate a
	// user's standing factors, so gate them behind a fresh proof of possession.
	r.Group(func(r chi.Router) {
		r.Use(RequireRecentMFA(h.Service, defaultStepUpWindow))
		r.Delete("/mfa/totp", h.disable)
		r.Post("/mfa/recovery-codes/regenerate", h.regenerateRecovery)
	})
}

// auditActor builds the actor portion of an audit row from the request
// principal. Returns ("", "system") for unauthenticated calls.
func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
}

type startEnrollInput struct {
	Account string `json:"account"`
}

func (h *Handler) startEnroll(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in startEnrollInput
	_ = httpx.DecodeJSON(r, &in)
	if in.Account == "" {
		in.Account = p.Subject
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	out, err := h.Service.StartEnroll(ctx, tx, *p.UserID, in.Account)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	tenantID := p.TenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_enroll_started",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type confirmEnrollInput struct {
	Code string `json:"code"`
}

func (h *Handler) confirmEnroll(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in confirmEnrollInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	codes, err := h.Service.ConfirmEnroll(ctx, tx, *p.UserID, in.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_enrolled",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"recovery_codes_minted": len(codes)},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": codes,
		"warning":        "store these once; they will not be shown again",
	})
}

type verifyInput struct {
	Code string `json:"code"`
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	result, err := h.Service.Verify(ctx, tx, *p.UserID, in.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Record the verification for step-up: any successful factor (TOTP or a
	// recovery code) refreshes the user's recent-verification window.
	method := "totp"
	if result.UsedRecoveryCode {
		method = "recovery_code"
	}
	if err := h.Service.RecordVerification(ctx, tx, *p.UserID, method); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Only audit when a recovery code was consumed — every successful
	// TOTP verify is high-frequency and not interesting for the chain.
	if result.UsedRecoveryCode {
		actorID, actorType := auditActor(r)
		target := *p.UserID
		meta := map[string]any{}
		if result.RecoveryCodeID != nil {
			meta["recovery_code_id"] = *result.RecoveryCodeID
		}
		if err := audit.Record(ctx, tx, audit.Event{
			TenantID:     p.TenantID,
			ActorUserID:  actorID,
			ActorType:    actorType,
			Action:       "mfa.recovery_code_used",
			ResourceType: "user",
			ResourceID:   &target,
			IP:           httpx.ClientIP(r),
			UserAgent:    r.UserAgent(),
			RequestID:    httpx.RequestID(r),
			Metadata:     meta,
		}); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.Disable(ctx, tx, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_disabled",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) recoveryStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	st, err := h.Service.RecoveryStatus(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) regenerateRecovery(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	out, err := h.Service.Regenerate(ctx, tx, *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.recovery_codes_regenerated",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"count": len(out)},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": out,
		"warning":        "store these once; they will not be shown again",
	})
}

// --- OTP factor handlers ---

type enrollOTPInput struct {
	Channel     string `json:"channel"`
	Destination string `json:"destination"`
}

func (h *Handler) listOTPFactors(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.ListOTPFactors(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) enrollOTPStart(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in enrollOTPInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	factorID, err := h.Service.EnrollOTPStart(r.Context(), *p.UserID, in.Channel, in.Destination)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"factor_id": factorID, "message": "verification code sent"})
}

func (h *Handler) enrollOTPConfirm(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	factorID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.EnrollOTPConfirm(ctx, tx, *p.UserID, factorID, in.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.otp_factor_added",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h *Handler) challengeOTP(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	factorID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.ChallengeOTP(r.Context(), *p.UserID, factorID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"message": "verification code sent"})
}

func (h *Handler) deleteOTPFactor(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	factorID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.DeleteOTPFactor(ctx, tx, *p.UserID, factorID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.otp_factor_removed",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) verifyOTP(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	ok, err := h.Service.VerifyOTP(ctx, tx, *p.UserID, in.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("invalid code"))
		return
	}
	if err := h.Service.RecordVerification(ctx, tx, *p.UserID, "otp"); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// --- WebAuthn second-factor handlers ---

func (h *Handler) webauthnChallenge(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented.WithDetail("webauthn factor not enabled"))
		return
	}
	sessionID, options, err := h.WebAuthn.BeginMFA(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type webauthnVerifyInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

func (h *Handler) webauthnVerify(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented.WithDetail("webauthn factor not enabled"))
		return
	}
	var in webauthnVerifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.WebAuthn.FinishMFA(ctx, *p.UserID, in.SessionID, in.Credential); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// FinishMFA has no surrounding tx (the assertion verify already committed its
	// sign-count update), so record the step-up + audit in their own tx.
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.RecordVerification(ctx, tx, *p.UserID, "webauthn"); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.webauthn_verified",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// --- Step-up status ---

func (h *Handler) stepUpStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ok, verifiedAt, err := h.Service.RecentlyVerified(r.Context(), *p.UserID, defaultStepUpWindow)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recently_verified": ok,
		"verified_at":       verifiedAt,
		"window_seconds":    int(defaultStepUpWindow.Seconds()),
	})
}
