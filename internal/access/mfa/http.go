package mfa

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// WebAuthnVerifier asserts a signed-in user's passkeys as a second factor;
// FinishMFATx does so inside the caller's transaction. It is satisfied by
// *passkey.Service; the interface keeps package mfa from importing package
// passkey.
type WebAuthnVerifier interface {
	BeginMFA(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialAssertion, error)
	FinishMFA(ctx context.Context, userID, sessionID uuid.UUID, cred json.RawMessage) error
	FinishMFATx(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, cred json.RawMessage) error
}

// Handler serves the MFA routes. WebAuthn, when set, offers the user's passkeys
// as a second factor (POST /mfa/webauthn/...). PairingThrottle, when set, wraps
// the public pairing-code claim route, where a wrong code is a guess.
type Handler struct {
	Service         *Service
	WebAuthn        WebAuthnVerifier
	PairingThrottle func(http.Handler) http.Handler
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// tenant's plan. Satisfied by operations/entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// Mount registers the second-factor routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/mfa/totp", h.totpStatus)
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

	// Push authenticator device management (authenticated user).
	r.Get("/mfa/push/devices", h.listPushDevices)
	r.Post("/mfa/push/devices", h.registerPushDevice)
	r.Delete("/mfa/push/devices/{id}", h.revokePushDevice)
	// A pairing code links a phone without copying an access token.
	r.Post("/mfa/push/pairing", h.createPushPairing)
	r.Get("/mfa/push/pairing/{id}", h.getPushPairing)
	r.Delete("/mfa/push/pairing/{id}", h.withdrawPushPairing)

	// Step-up status — lets a client decide whether to prompt before a
	// sensitive action.
	r.Get("/mfa/step-up/status", h.stepUpStatus)
	// Stepping up with a linked phone: send it a request, then complete the
	// step-up once it is approved.
	r.Post("/mfa/push/step-up", h.startStepUpPush)
	r.Post("/mfa/push/step-up/{id}/complete", h.completeStepUpPush)

	// Sensitive MFA actions require a step-up of the calling session:
	// disabling MFA wholesale and regenerating recovery codes both invalidate a
	// user's standing factors, so gate them behind a fresh proof of possession.
	r.Group(func(r chi.Router) {
		r.Use(RequireRecentMFA(h.Service))
		r.Delete("/mfa/totp", h.disable)
		r.Post("/mfa/recovery-codes/regenerate", h.regenerateRecovery)
	})
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
	// Setting up a new app replaces the confirmed one once confirmed, so while
	// one is held this needs the same step-up as switching it off. A first
	// setup needs none: there is no factor to step up with yet.
	enrolled, err := h.Service.IsEnrolled(ctx, *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if enrolled && !h.Service.passStepUp(w, r) {
		return
	}
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
	actorID, actorType := audit.ActorOf(r).Identity()
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
		Metadata:     map[string]any{"replacing": out.Replacing},
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
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeTOTPEnroll)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Registered before the transaction below so the refund only takes a
	// connection once that transaction has released its own — see Attempt.
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	var codes []string
	codes, opErr = h.Service.ConfirmEnroll(ctx, tx, attempt, in.Code)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	// Confirming the app proves possession of it, so the session that did it
	// is stepped up: the next sensitive action (regenerate recovery codes,
	// disable the app) needs no second code.
	if opErr = h.recordStepUp(ctx, tx, r, "totp"); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
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
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeFactorVerify)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	var result *VerifyResult
	result, opErr = h.Service.Verify(ctx, tx, attempt, in.Code)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	// The calling session is stepped up by the factor it just met.
	method := "totp"
	if result.UsedRecoveryCode {
		method = "recovery_code"
	}
	if opErr = h.recordStepUp(ctx, tx, r, method); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	// Only audit when a recovery code was consumed — every successful
	// TOTP verify is high-frequency and not interesting for the chain.
	if result.UsedRecoveryCode {
		actorID, actorType := audit.ActorOf(r).Identity()
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
	actorID, actorType := audit.ActorOf(r).Identity()
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

func (h *Handler) totpStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	st, err := h.Service.TOTPStatus(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
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
	actorID, actorType := audit.ActorOf(r).Identity()
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
	// SMS is a paid factor: the service refuses it unless the caller's
	// organisation's plan includes it (see SetPlan).
	factorID, err := h.Service.EnrollOTPStart(r.Context(), *p.UserID, p.TenantID, in.Channel, in.Destination)
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
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeOTPEnroll(factorID))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	if opErr = h.Service.EnrollOTPConfirm(ctx, tx, attempt, factorID, in.Code); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
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
	if err := h.Service.ChallengeOTP(r.Context(), *p.UserID, p.TenantID, factorID); err != nil {
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
	actorID, actorType := audit.ActorOf(r).Identity()
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
	attempt, err := h.Service.ReserveAttempt(ctx, *p.UserID, PurposeOTPVerify)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var opErr error
	defer func() { h.refund(ctx, attempt, opErr) }()
	tx, opErr := h.Service.Pool().Begin(ctx)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	defer tx.Rollback(ctx)
	var ok bool
	ok, opErr = h.Service.VerifyOTP(ctx, tx, attempt, in.Code)
	if opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	if !ok {
		httpx.WriteError(w, r, errs.ErrMFACodeInvalid)
		return
	}
	if opErr = h.recordStepUp(ctx, tx, r, "otp"); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	if opErr = tx.Commit(ctx); opErr != nil {
		httpx.WriteError(w, r, opErr)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}
