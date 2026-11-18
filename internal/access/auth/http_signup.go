package auth

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type signupInput struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,max=256"`
	DisplayName string `json:"display_name" validate:"omitempty,max=200"`
}

func (h *Handler) signup(w http.ResponseWriter, r *http.Request) {
	// An email that already has an account gets the neutral answer of
	// NeutralSignupError, and every attempt takes at least signupFloor.
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in signupInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	pair, u, _, err := h.Service.Signup(r.Context(), SignupInput{
		Email:       in.Email,
		Password:    in.Password,
		DisplayName: in.DisplayName,
		Actor:       audit.ActorOf(r),
	})
	if err != nil {
		httpx.WriteError(w, r, NeutralSignupError(err))
		return
	}
	// Organization-less: no organization or roles; the user creates one from the UI.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"user":          u,
		"access_token":  pair.AccessToken,
		"token_type":    pair.TokenType,
		"expires_at":    pair.ExpiresAt,
		"refresh_token": pair.RefreshToken,
		"session_id":    pair.SessionID,
		"user_id":       pair.UserID,
	})
}

type registerInput struct {
	OrganizationID uuid.UUID `json:"organization_id" validate:"required"`
	Email          string    `json:"email" validate:"required,email"`
	Password       string    `json:"password" validate:"required,max=256"`
	DisplayName    string    `json:"display_name" validate:"omitempty,max=200"`
}

// register is the hosted self-registration endpoint. It creates the user in the
// client's organization, if self-registration is enabled, and sets the SSO cookie, or
// returns an enrolment challenge when the organization requires MFA. Like signup, it
// answers an email that already has an account neutrally, under a timing floor.
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	const registerFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, registerFloor)

	var in registerInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	u, res, err := h.Service.RegisterInOrganization(r.Context(), in.OrganizationID, in.Email, in.Password, in.DisplayName, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, NeutralSignupError(err))
		return
	}
	if res.MFARequired {
		body := res.Body()
		body["user_id"] = u.ID
		httpx.WriteJSON(w, http.StatusCreated, body)
		return
	}
	SetLoginSessionCookie(w, res.RawCookie, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user_id": u.ID})
}
