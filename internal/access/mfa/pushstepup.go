package mfa

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A linked phone is a second factor at sign-in, so it is one for step-up too:
// it counts as a factor held (an account whose only factor is a phone is asked
// to step up like any other), and a session steps up by approving a request
// on it. An organisation that counts only push for step-up can then be
// satisfied.

const pushActionStepUp = "step_up"

// startStepUpPush (POST /v1/mfa/push/step-up) sends a step-up request for the
// calling session to every phone the person has linked. 202 with the
// request's id and expiry; complete it once approved.
func (h *Handler) startStepUpPush(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ctx := r.Context()
	var linked bool
	if err := h.Service.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.mfa_push_devices WHERE user_id = $1)`, *p.UserID).Scan(&linked); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !linked {
		httpx.WriteError(w, r, errs.ErrMFAPushDeviceNotFound)
		return
	}
	id, err := h.Service.CreatePushChallenge(ctx, *p.UserID, pushActionStepUp, PushChallengeContext{
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), Timestamp: time.Now().UTC().Format(time.RFC3339),
		SessionID: p.SessionID.String(),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ch, err := h.Service.GetPushChallenge(ctx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_id": id, "expires_at": ch.ExpiresAt})
}

// completeStepUpPush (POST /v1/mfa/push/step-up/{id}/complete) records the
// calling session's step-up once its request has been approved on the phone,
// and spends the request. 409 mfa.push_pending while it awaits an answer; a
// denied, spent or other session's request is invalid; an unanswered one past
// its expiry has expired.
func (h *Handler) completeStepUpPush(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrMFAPushChallengeInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	q := h.Service.q.WithTx(tx)
	row, err := q.PushChallengeForStepUp(ctx, dbgen.PushChallengeForStepUpParams{ID: id, UserID: *p.UserID})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		httpx.WriteError(w, r, errs.ErrMFAPushChallengeInvalid)
		return
	case err != nil:
		httpx.WriteError(w, r, err)
		return
	}
	if row.Action != pushActionStepUp || row.SessionID != p.SessionID.String() {
		httpx.WriteError(w, r, errs.ErrMFAPushChallengeInvalid)
		return
	}
	status := row.Status
	if status == "pending" && !time.Now().Before(row.ExpiresAt) {
		status = "expired"
	}
	switch status {
	case "pending":
		httpx.WriteError(w, r, errs.ErrMFAPushPending)
		return
	case "expired":
		httpx.WriteError(w, r, errs.ErrMFAPushChallengeExpired)
		return
	case "approved":
	default:
		httpx.WriteError(w, r, errs.ErrMFAPushChallengeInvalid)
		return
	}
	if err := h.recordStepUp(ctx, tx, r, "push"); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := q.SpendPushChallenge(ctx, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "approved"})
}
