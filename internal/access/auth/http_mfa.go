package auth

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// mfaLoginInput answers a sign-in's second-factor challenge with exactly one
// proof: a code, a passkey assertion, or push once the push request is approved.
// An enrolment challenge takes the code confirming the new authenticator app, or
// skip while setup may still be postponed.
type mfaLoginInput struct {
	MFAToken string        `json:"mfa_token" validate:"required"`
	Code     string        `json:"code"`
	Passkey  *PasskeyProof `json:"passkey"`
	Push     bool          `json:"push"`
	Skip     bool          `json:"skip"`
	// Remember opts into adaptive MFA on the hosted flow: trust this device so
	// future logins from it can skip the second factor (honoured only when the
	// organization has enabled it). Ignored by the token-flow /v1/auth/mfa endpoint.
	Remember bool `json:"remember"`
}

// mfaLogin completes a two-step login: it exchanges the mfa_token from /login
// plus a proof for a full token pair — with the new recovery codes when the
// proof confirmed an authenticator app set up for the challenge.
func (h *Handler) mfaLogin(w http.ResponseWriter, r *http.Request) {
	var in mfaLoginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	proof, err := in.proof()
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, codes, err := h.Service.CompleteMFALoginWith(r.Context(), in.MFAToken, proof, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(codes) > 0 {
		httpx.WriteJSON(w, http.StatusOK, struct {
			*TokenPair
			RecoveryCodes []string `json:"recovery_codes"`
		}{pair, codes})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

// proof is the one proof the input carries, or a validation error naming the
// problem.
func (in mfaLoginInput) proof() (MFAProof, error) {
	n := 0
	if in.Code != "" {
		n++
	}
	if in.Passkey != nil {
		n++
	}
	if in.Push {
		n++
	}
	if in.Skip {
		n++
	}
	if n != 1 {
		return MFAProof{}, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "code", Code: "required",
			Message: "Give exactly one of a code, a passkey assertion, push, or skip.",
		}})
	}
	return MFAProof{Code: in.Code, Passkey: in.Passkey, Push: in.Push, Skip: in.Skip}, nil
}

type mfaTokenInput struct {
	MFAToken string    `json:"mfa_token" validate:"required"`
	FactorID uuid.UUID `json:"factor_id"`
}

func (h *Handler) decodeMFAToken(w http.ResponseWriter, r *http.Request) (mfaTokenInput, bool) {
	var in mfaTokenInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return in, false
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return in, false
	}
	return in, true
}

// mfaSendCode sends a code to one of the challenged person's email or SMS
// factors (factor_id, from the challenge's factors).
func (h *Handler) mfaSendCode(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	if err := h.Service.SendMFACode(r.Context(), in.MFAToken, in.FactorID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// mfaPasskeyBegin starts the passkey assertion that can meet the challenge.
func (h *Handler) mfaPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	sessionID, options, err := h.Service.BeginMFAPasskey(r.Context(), in.MFAToken)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"session_id": sessionID, "publicKey": options})
}

// mfaPush sends the push approval request that can meet the challenge, and
// returns the number to show for the phone to match; the client then
// completes with push: true, which answers mfa.push_pending until the request
// is approved.
func (h *Handler) mfaPush(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	expires, number, err := h.Service.StartMFAPush(r.Context(), in.MFAToken, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"expires_at": expires, "number": number})
}

// mfaEnroll starts the authenticator app that meets an enrolment challenge
// and returns its secret and otpauth:// provisioning URL; a code from the app
// then completes the challenge.
func (h *Handler) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decodeMFAToken(w, r)
	if !ok {
		return
	}
	out, err := h.Service.StartMFAEnrollment(r.Context(), in.MFAToken, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
