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
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

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

// StepUp is a session's step-up as its organisation judges it. Met reports
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
	if row.VerifiedAt.Valid {
		at := row.VerifiedAt.Time
		st.VerifiedAt = &at
	}
	if row.Method != nil {
		st.Method = *row.Method
	}
	if len(st.Methods) == 0 {
		st.Methods = nil
	}
	return st, nil
}

// defaultStepUpWindow is how long a step-up lasts where nothing else is known
// (no session): the organisation default the migration also uses.
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
// StepUpWhenFactorHeld a person holding no counted factor can set one up, as
// they have nothing to step up with.
type StepUpRule int

const (
	StepUpAlways         StepUpRule = iota + 1 // every call needs one
	StepUpWhenFactorHeld                       // needed while the person holds a factor that counts
)

// StepUpGate refuses a call to a listed route ("METHOD /pattern", chi syntax)
// with 403 step_up_required unless the calling session is stepped up, as the
// route's rule says. Unlisted routes pass. Mount it on the authenticated group
// after authorization, so only an authorized caller is ever asked.
func (s *Service) StepUpGate(routes map[string]StepUpRule) func(http.Handler) http.Handler {
	always, whenHeld := chi.NewRouter(), chi.NewRouter()
	noop := func(http.ResponseWriter, *http.Request) {}
	for route, rule := range routes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("mfa: step-up route without a method: " + route)
		}
		switch rule {
		case StepUpAlways:
			always.MethodFunc(method, pattern, noop)
		case StepUpWhenFactorHeld:
			whenHeld.MethodFunc(method, pattern, noop)
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
			case whenHeld.Match(chi.NewRouteContext(), r.Method, r.URL.Path):
				if p := httpx.PrincipalFromCtx(r.Context()); p != nil && p.UserID != nil {
					held, err := s.HoldsStepUpFactor(r.Context(), *p.UserID, p.TenantID)
					if err != nil {
						httpx.WriteError(w, r, err)
						return
					}
					if held && !s.passStepUp(w, r) {
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HoldsStepUpFactor reports whether userID holds a factor that tenantID (nil:
// none) counts for a step-up, so a step-up can be asked of them.
func (s *Service) HoldsStepUpFactor(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID) (bool, error) {
	tid := uuid.Nil
	if tenantID != nil {
		tid = *tenantID
	}
	row, err := s.q.StepUpFactorsHeld(ctx, dbgen.StepUpFactorsHeldParams{UserID: userID, TenantID: tid})
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
// counts within the window when the organisation counts every factor type.
func (s *Service) passStepUp(w http.ResponseWriter, r *http.Request) bool {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return false
	}
	if p.SessionID == nil && p.SignedInAt != nil {
		tid := uuid.Nil
		if p.TenantID != nil {
			tid = *p.TenantID
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

// auditStepUp records a step-up event for the request's principal in its own
// transaction. Best effort: the refusal or success it describes stands either
// way.
func (s *Service) auditStepUp(r *http.Request, action string, meta map[string]any) {
	ctx := r.Context()
	p := httpx.PrincipalFromCtx(ctx)
	if s.pool == nil {
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	actorID, actorType := audit.ActorOf(r).Identity()
	if p.SessionID != nil {
		meta["session_id"] = *p.SessionID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "user",
		ResourceID:   p.UserID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// recordStepUp records, inside tx, that the calling session met a second
// factor by method and audits it there. A principal without a session has
// nothing to step up, so only the factor check itself counted.
func (h *Handler) recordStepUp(ctx context.Context, tx pgx.Tx, r *http.Request, method string) error {
	p := httpx.PrincipalFromCtx(ctx)
	if p == nil || p.UserID == nil || p.SessionID == nil {
		return nil
	}
	if err := h.Service.RecordVerification(ctx, tx, *p.UserID, *p.SessionID, method); err != nil {
		return err
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.step_up_verified",
		ResourceType: "user",
		ResourceID:   p.UserID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"method": method, "session_id": *p.SessionID},
	})
}

func (h *Handler) webauthnChallenge(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if h.WebAuthn == nil {
		httpx.WriteError(w, r, errs.ErrMFAWebAuthnUnavailable)
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
		httpx.WriteError(w, r, errs.ErrMFAWebAuthnUnavailable)
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
	if err := h.recordStepUp(ctx, tx, r, "webauthn"); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
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
