package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type PushDevice struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Platform   string    `json:"platform"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type PushChallenge struct {
	ID        uuid.UUID       `json:"id"`
	UserID    uuid.UUID       `json:"user_id"`
	Action    string          `json:"action"`
	Context   json.RawMessage `json:"context"`
	Status    string          `json:"status"`
	ExpiresAt time.Time       `json:"expires_at"`
	CreatedAt time.Time       `json:"created_at"`
}

// PushChallengeContext is the payload delivered via push notification and
// displayed in the app so the user can make an informed approve/deny decision.
type PushChallengeContext struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Location  string `json:"location,omitempty"`
	Timestamp string `json:"timestamp"`
}

// ── Service methods ───────────────────────────────────────────────────────────

// RegisterPushDevice upserts a device push token and returns the device record
// plus a one-time device_token the app must persist for future challenge-respond
// calls. On re-registration of the same push_token the device_token is rotated.
func (s *Service) RegisterPushDevice(ctx context.Context, userID uuid.UUID, name, pushToken, platform string) (PushDevice, string, error) {
	tok, err := randomHex(32)
	if err != nil {
		return PushDevice{}, "", err
	}
	row, err := s.q.UpsertPushDevice(ctx, dbgen.UpsertPushDeviceParams{
		UserID:      userID,
		Name:        name,
		PushToken:   pushToken,
		Platform:    platform,
		DeviceToken: tok,
	})
	if err != nil {
		return PushDevice{}, "", err
	}
	d := PushDevice{
		ID:         row.ID,
		Name:       row.Name,
		Platform:   row.Platform,
		CreatedAt:  row.CreatedAt,
		LastSeenAt: row.LastSeenAt,
	}
	return d, tok, nil
}

func (s *Service) ListPushDevices(ctx context.Context, userID uuid.UUID) ([]PushDevice, error) {
	rows, err := s.q.ListPushDevices(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]PushDevice, 0, len(rows))
	for _, r := range rows {
		out = append(out, PushDevice{
			ID:         r.ID,
			Name:       r.Name,
			Platform:   r.Platform,
			CreatedAt:  r.CreatedAt,
			LastSeenAt: r.LastSeenAt,
		})
	}
	return out, nil
}

func (s *Service) RevokePushDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	n, err := s.q.DeletePushDevice(ctx, dbgen.DeletePushDeviceParams{ID: deviceID, UserID: userID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrMFAPushDeviceNotFound
	}
	return nil
}

// CreatePushChallenge inserts a pending challenge, fans out a push notification
// to every registered device of the user, and returns the challenge ID.
func (s *Service) CreatePushChallenge(ctx context.Context, userID uuid.UUID, action string, pctx PushChallengeContext) (uuid.UUID, error) {
	ctxJSON, err := json.Marshal(pctx)
	if err != nil {
		return uuid.Nil, err
	}
	ch, err := s.q.InsertPushChallenge(ctx, dbgen.InsertPushChallengeParams{
		UserID:  userID,
		Action:  action,
		Context: ctxJSON,
	})
	if err != nil {
		return uuid.Nil, err
	}
	tokens, err := s.q.ListPushTokensByUser(ctx, userID)
	if err != nil {
		return uuid.Nil, err
	}
	for _, tok := range tokens {
		_ = s.sendExpoPush(ctx, tok, ch.ID, action)
	}
	return ch.ID, nil
}

// GetPushChallenge returns the challenge for public polling / display.
func (s *Service) GetPushChallenge(ctx context.Context, id uuid.UUID) (*PushChallenge, error) {
	row, err := s.q.GetPushChallenge(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
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
func (s *Service) RespondToPushChallenge(ctx context.Context, challengeID, userID uuid.UUID, deviceToken string, approved bool) error {
	// Verify the device_token belongs to one of this user's devices.
	_, err := s.q.VerifyDeviceToken(ctx, dbgen.VerifyDeviceTokenParams{
		UserID:      userID,
		DeviceToken: deviceToken,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrMFAPushUnauthorized
	}
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	row, err := s.q.WithTx(tx).GetPushChallengeForUpdate(ctx, challengeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if row.UserID != userID {
		return errs.ErrMFAPushUnauthorized
	}
	if row.Status != "pending" {
		return errs.ErrMFAPushChallengeInvalid
	}
	if time.Now().UTC().After(row.ExpiresAt) {
		return errs.ErrMFAPushChallengeExpired
	}

	status := "denied"
	if approved {
		status = "approved"
	}
	if err := s.q.WithTx(tx).UpdatePushChallengeStatus(ctx, dbgen.UpdatePushChallengeStatusParams{
		ID:     challengeID,
		Status: status,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ── Expo push helper ──────────────────────────────────────────────────────────

type expoPushMessage struct {
	To    string         `json:"to"`
	Title string         `json:"title"`
	Body  string         `json:"body"`
	Data  map[string]any `json:"data"`
}

func (s *Service) sendExpoPush(ctx context.Context, pushToken string, challengeID uuid.UUID, action string) error {
	msg := expoPushMessage{
		To:    pushToken,
		Title: fmt.Sprintf("Sign-in request: %s", action),
		Body:  "Tap to approve or deny this request.",
		Data: map[string]any{
			"challenge_id": challengeID.String(),
			"action":       action,
		},
	}
	payload, err := json.Marshal([]expoPushMessage{msg})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.pushURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return nil
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// MountPublic mounts the unauthenticated challenge endpoints (polled by the
// browser waiting for approval, and called by the mobile app responding to a
// push).
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/mfa/push/challenges/{id}", h.getPushChallenge)
	r.Post("/mfa/push/challenges/{id}/respond", h.respondToPushChallenge)
}

// --- device management (authenticated) ---

type registerPushDeviceInput struct {
	Name      string `json:"name"`
	PushToken string `json:"push_token"`
	Platform  string `json:"platform"`
}

func (h *Handler) listPushDevices(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	devices, err := h.Service.ListPushDevices(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": devices})
}

func (h *Handler) registerPushDevice(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in registerPushDeviceInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.PushToken == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("push_token required"))
		return
	}
	if in.Platform != "ios" && in.Platform != "android" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("platform must be ios or android"))
		return
	}
	device, deviceToken, err := h.Service.RegisterPushDevice(r.Context(), *p.UserID, in.Name, in.PushToken, in.Platform)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"device":       device,
		"device_token": deviceToken,
		"warning":      "store device_token securely; it will not be shown again",
	})
}

func (h *Handler) revokePushDevice(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	deviceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.RevokePushDevice(r.Context(), *p.UserID, deviceID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- public challenge endpoints ---

func (h *Handler) getPushChallenge(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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
}

func (h *Handler) respondToPushChallenge(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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
	if err := h.Service.RespondToPushChallenge(r.Context(), id, in.UserID, in.DeviceToken, in.Approved); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": map[bool]string{true: "approved", false: "denied"}[in.Approved]})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
