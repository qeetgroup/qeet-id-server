package mfa

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A linked phone is a step-up factor too: holding one means a step-up can be
// asked for, and approving a request on it steps the session up.

const pushActionStepUp = "step_up"

// startStepUpPush (POST /v1/mfa/push/step-up) sends a step-up request for the
// calling session to every phone the person has linked. 202 with the
// request's id, expiry and the number to show for the phone to match;
// complete it once approved.
func (h *Handler) startStepUpPush(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ctx := r.Context()
	linked, err := h.Service.q.HasPushDevice(ctx, *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !linked {
		httpx.WriteError(w, r, ErrPushDeviceNotFound)
		return
	}
	id, number, err := h.Service.CreatePushChallenge(ctx, *p.UserID, pushActionStepUp, PushChallengeContext{
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
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_id": id, "expires_at": ch.ExpiresAt, "number": number})
}

// completeStepUpPush (POST /v1/mfa/push/step-up/{id}/complete) records the
// calling session's step-up once its request is approved, and spends it.
// 409 mfa.push_pending while unanswered; a denied, spent or other session's
// request is invalid, and a pending one past its expiry has expired.
func (h *Handler) completeStepUpPush(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrPushChallengeInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.CompleteStepUpPush(r.Context(), *p.UserID, id, CallerOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "approved"})
}

// CompleteStepUpPush steps up by's session once userID's step-up request id,
// raised for that session, is approved, and spends the request, recorded as
// by's. ErrMFAPushPending while unanswered; a denied, spent or other session's
// request is invalid, and a pending one past its expiry has expired.
func (s *Service) CompleteStepUpPush(ctx context.Context, userID, id uuid.UUID, by Caller) error {
	if by.SessionID == nil {
		return errs.ErrUnauthorized
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		q := s.q.WithTx(tx)
		row, err := q.PushChallengeForStepUp(ctx, dbgen.PushChallengeForStepUpParams{ID: id, UserID: userID})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrPushChallengeInvalid
		case err != nil:
			return err
		}
		if row.Action != pushActionStepUp || row.SessionID != by.SessionID.String() {
			return ErrPushChallengeInvalid
		}
		status := row.Status
		if status == "pending" && !time.Now().Before(row.ExpiresAt) {
			status = "expired"
		}
		switch status {
		case "pending":
			return errs.ErrMFAPushPending
		case "expired":
			return errs.ErrMFAPushChallengeExpired
		case "approved":
		default:
			return ErrPushChallengeInvalid
		}
		if err := s.recordStepUp(ctx, tx, userID, by, "push"); err != nil {
			return err
		}
		return q.SpendPushChallenge(ctx, id)
	})
}
