package mfa

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Step-up MFA. A step-up records that one session met a second factor
// recently, so a factor proved in one browser never unlocks another. Each
// organization sets how long it lasts (step_up_window, default 5 minutes) and
// which factor types count (step_up_methods, default any).

// RecordVerification records that sessionID, one of userID's own live
// sessions, met a second factor by method ("totp", "recovery_code", "otp",
// "webauthn" or "push"). For any other session nothing is recorded, so the
// step-up stays unmet. Callers pass the tx the factor's own write runs in.
func (s *Service) RecordVerification(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, method string) error {
	return s.q.WithTx(tx).RecordStepUp(ctx, dbgen.RecordStepUpParams{
		Method:    method,
		SessionID: sessionID,
		UserID:    userID,
	})
}

// StepUp is a session's step-up as its organization judges it. Met reports
// whether a counted factor was met within Window. VerifiedAt and Method are the
// latest step-up, counted or not. Methods are the counted types (nil: any).
type StepUp struct {
	Met        bool
	VerifiedAt *time.Time
	Method     string
	Window     time.Duration
	Methods    []string
}

// StepUpState reads sessionID's step-up. A principal without a session (an API
// key, an agent, a hosted-login cookie) cannot step up: it reads as unmet.
func (s *Service) StepUpState(ctx context.Context, userID uuid.UUID, sessionID *uuid.UUID) (StepUp, error) {
	if sessionID == nil {
		return StepUp{Window: defaultStepUpWindow}, nil
	}
	row, err := s.q.StepUpState(ctx, dbgen.StepUpStateParams{SessionID: *sessionID, UserID: userID})
	if err != nil {
		return StepUp{}, err
	}
	st := StepUp{
		Met:     row.Fresh && row.MethodCounts,
		Window:  time.Duration(row.WindowSeconds) * time.Second,
		Methods: row.StepUpMethods,
	}
	st.VerifiedAt = row.VerifiedAt
	if row.Method != nil {
		st.Method = *row.Method
	}
	if len(st.Methods) == 0 {
		st.Methods = nil
	}
	return st, nil
}

// defaultStepUpWindow is how long a step-up lasts where nothing else is known
// (no session): the organization default the migration also uses.
const defaultStepUpWindow = 5 * time.Minute

// RequireRecentMFA gates a handler behind a step-up of the calling session.
// Otherwise it refuses with 403 step_up_required, listing the factor types
// that count in allowed_methods (omitted when any does), and audits the refusal.
func RequireRecentMFA(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if svc.passStepUp(w, r) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// StepUpRule says when a route needs a step-up of the calling session. Under
// StepUpOrRecentSignIn a person holding no counted factor has nothing to step
// up with, so a sign-in within the step-up window stands in for one.
type StepUpRule int

const (
	StepUpAlways         StepUpRule = iota + 1 // every call needs one
	StepUpOrRecentSignIn                       // a step-up while the person holds a factor that counts, else a recent sign-in
)

// StepUpGate refuses a call to a listed route ("METHOD /pattern", chi syntax)
// with 403 step_up_required unless the calling session is stepped up, as the
// route's rule says. Unlisted routes pass. Mount it on the authenticated group
// after authorization, so only an authorized caller is ever asked.
func (s *Service) StepUpGate(routes map[string]StepUpRule) func(http.Handler) http.Handler {
	always, orRecent := chi.NewRouter(), chi.NewRouter()
	noop := func(http.ResponseWriter, *http.Request) {}
	for route, rule := range routes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("mfa: step-up route without a method: " + route)
		}
		switch rule {
		case StepUpAlways:
			always.MethodFunc(method, pattern, noop)
		case StepUpOrRecentSignIn:
			orRecent.MethodFunc(method, pattern, noop)
		default:
			panic("mfa: step-up route without a rule: " + route)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case always.Match(chi.NewRouteContext(), r.Method, r.URL.Path):
				if !s.passStepUp(w, r) {
					return
				}
			case orRecent.Match(chi.NewRouteContext(), r.Method, r.URL.Path):
				p := httpx.PrincipalFromCtx(r.Context())
				if p == nil || p.UserID == nil {
					httpx.WriteError(w, r, errs.ErrUnauthorized)
					return
				}
				held, err := s.HoldsStepUpFactor(r.Context(), *p.UserID, p.OrganizationID)
				if err != nil {
					httpx.WriteError(w, r, err)
					return
				}
				pass := s.passRecentSignIn
				if held {
					pass = s.passStepUp
				}
				if !pass(w, r) {
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HoldsStepUpFactor reports whether userID holds a factor that organizationID (nil:
// none) counts for a step-up, so a step-up can be asked of them.
func (s *Service) HoldsStepUpFactor(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID) (bool, error) {
	tid := uuid.Nil
	if organizationID != nil {
		tid = *organizationID
	}
	row, err := s.q.StepUpFactorsHeld(ctx, dbgen.StepUpFactorsHeldParams{UserID: userID, OrganizationID: tid})
	if err != nil {
		return false, err
	}
	counts := func(methods ...string) bool {
		if len(row.StepUpMethods) == 0 {
			return true
		}
		for _, m := range methods {
			for _, allowed := range row.StepUpMethods {
				if m == allowed {
					return true
				}
			}
		}
		return false
	}
	return (row.Totp && counts("totp", "recovery_code")) || (row.Otp && counts("otp")) ||
		(row.Passkeys && counts("webauthn")) || (row.Push && counts("push")), nil
}

// passStepUp reports whether the request's session is stepped up. If not, it
// has already written the refusal (401 with no user, else an audited 403
// step_up_required). A hosted-login principal has no session; its sign-in
// counts within the window when the organization counts every factor type.
func (s *Service) passStepUp(w http.ResponseWriter, r *http.Request) bool {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return false
	}
	if p.SessionID == nil && p.SignedInAt != nil {
		tid := uuid.Nil
		if p.OrganizationID != nil {
			tid = *p.OrganizationID
		}
		org, err := s.q.OrgStepUpPolicy(r.Context(), tid)
		if err != nil {
			httpx.WriteError(w, r, err)
			return false
		}
		if org.EveryFactor && time.Since(*p.SignedInAt) <= time.Duration(org.WindowSeconds)*time.Second {
			return true
		}
	}
	st, err := s.StepUpState(r.Context(), *p.UserID, p.SessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return false
	}
	if !st.Met {
		s.auditStepUp(r, "mfa.step_up_required", map[string]any{"route": r.URL.Path})
		meta := map[string]any{"window_seconds": int(st.Window.Seconds())}
		if st.Methods != nil {
			meta["allowed_methods"] = st.Methods
		}
		httpx.WriteError(w, r, errs.ErrStepUpRequired.WithMetadata(meta))
		return false
	}
	return true
}

// passRecentSignIn reports whether the request's principal signed in within
// its organization's step-up window: its session's sign-in, or a hosted-login
// principal's. If not, it has already written an audited 403
// recent_sign_in_required.
func (s *Service) passRecentSignIn(w http.ResponseWriter, r *http.Request) bool {
	p := httpx.PrincipalFromCtx(r.Context())
	var recent bool
	var window int64
	switch {
	case p.SessionID != nil:
		row, err := s.q.SessionSignedInRecently(r.Context(), dbgen.SessionSignedInRecentlyParams{SessionID: *p.SessionID, UserID: *p.UserID})
		if err != nil {
			httpx.WriteError(w, r, err)
			return false
		}
		recent, window = row.Recent, row.WindowSeconds
	default:
		tid := uuid.Nil
		if p.OrganizationID != nil {
			tid = *p.OrganizationID
		}
		org, err := s.q.OrgStepUpPolicy(r.Context(), tid)
		if err != nil {
			httpx.WriteError(w, r, err)
			return false
		}
		window = org.WindowSeconds
		recent = p.SignedInAt != nil && time.Since(*p.SignedInAt) <= time.Duration(window)*time.Second
	}
	if !recent {
		s.auditStepUp(r, "auth.recent_sign_in_required", map[string]any{"route": r.URL.Path})
		httpx.WriteError(w, r, ErrRecentSignIn.WithMetadata(map[string]any{"window_seconds": window}))
		return false
	}
	return true
}

// auditStepUp records a step-up event for the request's principal in its own
// transaction. Best effort: the refusal or success it describes stands either
// way.
func (s *Service) auditStepUp(r *http.Request, action string, meta map[string]any) {
	by := CallerOf(r)
	if by.SessionID != nil {
		meta["session_id"] = *by.SessionID
	}
	userID := postgres.ZeroIfNull(httpx.PrincipalFromCtx(r.Context()).UserID)
	_ = audit.RecordAlone(r.Context(), s.pool, by.event(action, userID, meta))
}

// recordStepUp records, inside tx, that by's session met a second factor of
// userID's by method and audits it there. A caller without a session has
// nothing to step up, so only the factor check itself counted.
func (s *Service) recordStepUp(ctx context.Context, tx pgx.Tx, userID uuid.UUID, by Caller, method string) error {
	if by.SessionID == nil {
		return nil
	}
	if err := s.RecordVerification(ctx, tx, userID, *by.SessionID, method); err != nil {
		return err
	}
	return audit.Record(ctx, tx, by.event("mfa.step_up_verified", userID, map[string]any{"method": method, "session_id": *by.SessionID}))
}

// RecordPasskeyStepUp steps up by's session by a passkey of userID's just
// asserted, recorded as by's. The assertion has committed on its own (its
// sign count), so this runs in a transaction of its own.
func (s *Service) RecordPasskeyStepUp(ctx context.Context, userID uuid.UUID, by Caller) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := s.recordStepUp(ctx, tx, userID, by, "webauthn"); err != nil {
			return err
		}
		return audit.Record(ctx, tx, by.event("mfa.webauthn_verified", userID, nil))
	})
}

func (h *Handler) webauthnChallenge(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		httpx.WriteError(w, r, ErrWebAuthnUnavailable)
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
		httpx.WriteError(w, r, ErrWebAuthnUnavailable)
		return
	}
	var in webauthnVerifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.WebAuthn.FinishMFA(r.Context(), *p.UserID, in.SessionID, in.Credential); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RecordPasskeyStepUp(r.Context(), *p.UserID, CallerOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h *Handler) stepUpStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	st, err := h.Service.StepUpState(r.Context(), *p.UserID, p.SessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recently_verified": st.Met,
		"verified_at":       st.VerifiedAt,
		"window_seconds":    int(st.Window.Seconds()),
		"allowed_methods":   st.Methods,
	})
}
