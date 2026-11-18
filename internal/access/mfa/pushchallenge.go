package mfa

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Push requests are bounded so a person isn't worn down into approving one:
// a few in ten minutes, and none for the rest of an hour in which they denied
// several.
const (
	maxPushPer10Minutes   = 5
	maxPushDenialsPerHour = 3
)

// CreatePushChallenge records a pending challenge, sends it to the user's linked phones and returns
// its ID and the number to send back, shown where it was asked. ErrMFAPushLimited past the bounds;
// ErrMFAPushDeliveryFailed, closing it, when no phone accepted. A phone whose push service has no
// credentials here isn't a failure: it finds the request when the app next opens.
func (s *Service) CreatePushChallenge(ctx context.Context, userID uuid.UUID, action string, pctx PushChallengeContext) (uuid.UUID, int, error) {
	if pctx.Location == "" {
		pctx.Location = pushLocation(ctx)
	}
	ctxJSON, err := json.Marshal(pctx)
	if err != nil {
		return uuid.Nil, 0, err
	}
	number, err := matchNumber()
	if err != nil {
		return uuid.Nil, 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, 0, err
	}
	defer tx.Rollback(ctx)
	// One request at a time per person, so two can't both pass the bounds.
	// Raw SQL: pg_advisory_xact_lock returns void, which sqlc cannot model.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mfa-push:' || $1::text, 0))`, userID); err != nil {
		return uuid.Nil, 0, err
	}
	recent, err := s.q.WithTx(tx).RecentPushChallenges(ctx, userID)
	if err != nil {
		return uuid.Nil, 0, err
	}
	if recent.Sent >= maxPushPer10Minutes || recent.Denied >= maxPushDenialsPerHour {
		return uuid.Nil, 0, ErrPushLimited
	}
	ch, err := s.q.WithTx(tx).InsertPushChallenge(ctx, dbgen.InsertPushChallengeParams{
		UserID:      userID,
		Action:      action,
		Context:     ctxJSON,
		MatchNumber: &number,
	})
	if err != nil {
		return uuid.Nil, 0, err
	}
	tokens, err := s.loadPushTokens(ctx, tx, userID)
	if err != nil {
		return uuid.Nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, 0, err
	}
	if !s.pushConfigured() {
		return ch.ID, int(number), nil // push delivery not configured
	}
	delivered := 0 // sent, or left for the app to find when it opens
	for _, t := range tokens {
		err := s.deliverPush(ctx, t, signInMessage(ch.ID, action))
		switch {
		case err == nil:
			delivered++
		case errors.Is(err, errPushDeviceGone):
			// The app was removed from that phone: stop sending to it.
			s.retirePushToken(ctx, userID, t.token)
			slog.Info("push device no longer registered; retired", "challenge_id", ch.ID, "device_ref", pushTokenRef(t.token))
		case errors.Is(err, errPushNotConfigured):
			delivered++
			slog.Warn("push service for this phone is not configured", "challenge_id", ch.ID, "platform", t.platform, "device_ref", pushTokenRef(t.token))
		default:
			slog.Warn("push delivery failed", "challenge_id", ch.ID, "platform", t.platform, "device_ref", pushTokenRef(t.token), "err", err)
		}
	}
	if len(tokens) > 0 && delivered == 0 {
		// Nothing can answer it: close it now rather than leave the sign-in
		// waiting out its two minutes.
		_ = s.q.CloseUndeliveredPushChallenge(ctx, ch.ID)
		return uuid.Nil, 0, ErrPushDeliveryFailed
	}
	return ch.ID, int(number), nil
}

// matchNumber returns a random two-digit number, 10 to 99.
func matchNumber() (int16, error) {
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if b[0] < 180 { // 180 = 2 × 90, so every number is equally likely
			return 10 + int16(b[0]%90), nil
		}
	}
}

// GetPushChallenge returns the challenge for public polling / display. A
// pending challenge past its expiry is recorded and reported as expired, so the
// approval screen never offers to approve what can no longer be answered.
func (s *Service) GetPushChallenge(ctx context.Context, id uuid.UUID) (*PushChallenge, error) {
	row, err := s.q.GetPushChallenge(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if row.Status == "pending" && !time.Now().Before(row.ExpiresAt) {
		if err := s.q.ExpirePushChallenge(ctx, id); err != nil {
			return nil, err
		}
		row.Status = "expired"
	}
	return &PushChallenge{
		ID:        row.ID,
		UserID:    row.UserID,
		Action:    row.Action,
		Context:   row.Context,
		Status:    row.Status,
		ExpiresAt: row.ExpiresAt,
		CreatedAt: row.CreatedAt,
	}, nil
}

// RespondToPushChallenge validates the device_token, checks that the challenge
// is still pending and not expired, then updates its status to approved/denied.
// An approval must carry the challenge's number; with another it is denied,
// with ErrMFAPushNumberMismatch.
func (s *Service) RespondToPushChallenge(ctx context.Context, challengeID, userID uuid.UUID, deviceToken string, approved bool, number int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = s.q.WithTx(tx).PushDeviceByCredential(ctx, dbgen.PushDeviceByCredentialParams{UserID: userID, DeviceTokenHash: secretHash(deviceToken)})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPushUnauthorized
	}
	if err != nil {
		return err
	}

	row, err := s.q.WithTx(tx).GetPushChallengeForUpdate(ctx, challengeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if row.UserID != userID {
		return ErrPushUnauthorized
	}
	if row.Status != "pending" {
		return ErrPushChallengeInvalid
	}
	if time.Now().UTC().After(row.ExpiresAt) {
		return errs.ErrMFAPushChallengeExpired
	}

	mismatch := approved && row.MatchNumber != nil && int(*row.MatchNumber) != number
	status := "denied"
	if approved && !mismatch {
		status = "approved"
	}
	if err := s.q.WithTx(tx).UpdatePushChallengeStatus(ctx, dbgen.UpdatePushChallengeStatusParams{
		ID:     challengeID,
		Status: status,
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if mismatch {
		return ErrPushNumberMismatch
	}
	return nil
}

// listPendingPushChallenges → POST /v1/mfa/push/devices/{id}/pending: a linked phone asks for
// the sign-in requests waiting on its account, proving it is that device with its current
// device credential (sent in the body, never in a URL). The app calls it when it comes to the
// foreground, so a request whose push was delayed or dropped can still be answered.
func (h *Handler) listPendingPushChallenges(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in unlinkPushDeviceInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.DeviceToken == "" || in.UserID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("user_id and device_token required"))
		return
	}
	challenges, err := h.Service.PendingPushChallenges(r.Context(), id, in.UserID, in.DeviceToken)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"challenges": challenges})
}

// maxPendingPushChallenges bounds the pending list; creating requests is already limited to a
// few every ten minutes, so this is never reached in normal use.
const maxPendingPushChallenges = 10

// PendingPushChallenges returns the user's requests still waiting for an answer, newest first,
// for the linked phone deviceID. The phone proves itself with its device credential, which must
// not have expired; ErrMFAPushUnauthorized otherwise.
func (s *Service) PendingPushChallenges(ctx context.Context, deviceID, userID uuid.UUID, deviceToken string) ([]PushChallenge, error) {
	_, err := s.q.LinkedPushDevice(ctx, dbgen.LinkedPushDeviceParams{ID: deviceID, UserID: userID, DeviceTokenHash: secretHash(deviceToken)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPushUnauthorized
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListPendingPushChallenges(ctx, dbgen.ListPendingPushChallengesParams{UserID: userID, RowLimit: maxPendingPushChallenges})
	if err != nil {
		return nil, err
	}
	out := make([]PushChallenge, len(rows))
	for i, c := range rows {
		out[i] = PushChallenge{ID: c.ID, UserID: c.UserID, Action: c.Action, Context: c.Context, Status: c.Status,
			ExpiresAt: c.ExpiresAt, CreatedAt: c.CreatedAt}
	}
	return out, nil
}

func (h *Handler) getPushChallenge(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ch, err := h.Service.GetPushChallenge(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ch)
}

type respondToPushChallengeInput struct {
	UserID      uuid.UUID `json:"user_id"`
	DeviceToken string    `json:"device_token"`
	Approved    bool      `json:"approved"`
	Number      int       `json:"number"` // the number shown where the request was asked for
}

func (h *Handler) respondToPushChallenge(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in respondToPushChallengeInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.DeviceToken == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("device_token required"))
		return
	}
	if err := h.Service.RespondToPushChallenge(r.Context(), id, in.UserID, in.DeviceToken, in.Approved, in.Number); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": map[bool]string{true: "approved", false: "denied"}[in.Approved]})
}
