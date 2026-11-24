package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
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
// as a second factor (POST /mfa/webauthn/...). PairingThrottle wraps the public
// pairing-code claim route, where a wrong code is a guess.
type Handler struct {
	Service         *Service
	WebAuthn        WebAuthnVerifier
	PairingThrottle func(http.Handler) http.Handler
	// ActOnCheck refuses an administrator changing the sign-in methods of a
	// member who outranks them (rbac CheckActOn); nil refuses every change.
	ActOnCheck func(ctx context.Context, caller *httpx.Principal, organizationID, targetID uuid.UUID) error
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
	// Setting up a new app replaces the confirmed one once confirmed, so while
	// one is held this needs the same step-up as switching it off. A first
	// setup needs none: there is no factor to step up with yet.
	enrolled, err := h.Service.IsEnrolled(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if enrolled && !h.Service.passStepUp(w, r) {
		return
	}
	out, err := h.Service.StartEnroll(r.Context(), *p.UserID, in.Account, CallerOf(r))
	if err != nil {
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
	codes, err := h.Service.ConfirmEnroll(r.Context(), *p.UserID, in.Code, CallerOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.tellAccountChange(r.Context(), *p.UserID, "Two-step verification was turned on",
		"An authenticator app was set up for two-step verification on your Qeet ID account; its codes are now asked for when you sign in.")
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
	if _, err := h.Service.Verify(r.Context(), *p.UserID, in.Code, CallerOf(r)); err != nil {
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
	if err := h.Service.Disable(r.Context(), *p.UserID, CallerOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.tellAccountChange(r.Context(), *p.UserID, "Two-step verification was turned off",
		"The authenticator app was removed from your Qeet ID account, with its recovery codes, so its codes are no longer asked for when you sign in.")
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
	out, err := h.Service.Regenerate(r.Context(), *p.UserID, CallerOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.tellAccountChange(r.Context(), *p.UserID, "New recovery codes were made for your account",
		"New two-step verification recovery codes were made for your Qeet ID account. The ones you had before no longer work.")
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
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
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
	// organization's plan includes it (see SetPlan).
	factorID, err := h.Service.EnrollOTPStart(r.Context(), *p.UserID, p.OrganizationID, in.Channel, in.Destination)
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
	factorID, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.EnrollOTPConfirm(r.Context(), *p.UserID, factorID, in.Code, CallerOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.tellAccountChange(r.Context(), *p.UserID, "A way to get sign-in codes was added to your account",
		"A phone number or email address that receives two-step verification codes was added to your Qeet ID account.")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h *Handler) challengeOTP(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	factorID, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.ChallengeOTP(r.Context(), *p.UserID, p.OrganizationID, factorID); err != nil {
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
	factorID, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteOTPFactor(r.Context(), *p.UserID, factorID, CallerOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.tellAccountChange(r.Context(), *p.UserID, "A way to get sign-in codes was removed from your account",
		"A phone number or email address that received two-step verification codes was removed from your Qeet ID account.")
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
	if err := h.Service.VerifyOTP(r.Context(), *p.UserID, in.Code, CallerOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// MountPublic mounts the unauthenticated challenge endpoints (polled by the
// browser waiting for approval, and called by the mobile app responding to a
// push).
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/mfa/push/challenges/{id}", h.getPushChallenge)
	r.Post("/mfa/push/challenges/{id}/respond", h.respondToPushChallenge)
	// A linked phone removes itself with its own device credential: the app
	// holds no signed-in session to call the authenticated route with.
	r.Post("/mfa/push/devices/{id}/unlink", h.unlinkPushDevice)
	// A linked phone tells the server its new push token when the platform rotates it.
	r.Post("/mfa/push/devices/{id}/push-token", h.updatePushToken)
	// A linked phone asks for requests waiting on it, for when a push was late or lost.
	r.Post("/mfa/push/devices/{id}/pending", h.listPendingPushChallenges)
	// The mobile app links the phone with a pairing code, holding no session.
	r.With(h.PairingThrottle).Post("/mfa/push/pairing/claim", h.claimPushPairing)
}

// MountAdmin mounts an administrator's view of a member's linked phones, in
// the administrator's own organization (user.read / user.credentials).
func (h *Handler) MountAdmin(r chi.Router) {
	r.Get("/users/{id}/push-devices", h.listMemberPushDevices)
	r.Delete("/users/{id}/push-devices/{deviceID}", h.revokeMemberPushDevice)
}

// Check refuses a handler without the pairing-code throttle, so bootstrap
// stops at start rather than serve the claim route unthrottled.
func (h *Handler) Check() error {
	if h.PairingThrottle == nil {
		return errors.New("mfa: the second-factor handler needs a pairing throttle")
	}
	return nil
}
