package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	if s.box == nil {
		return PushDevice{}, "", errs.ErrInternalServer.WithDetail("MFA secret encryption is unavailable")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PushDevice{}, "", err
	}
	defer tx.Rollback(ctx)
	if _, err := s.loadPushTokens(ctx, tx, userID); err != nil {
		return PushDevice{}, "", err
	}
	pushTokenHash := secretHash(pushToken)
	ciphertext, nonce, err := s.box.Seal(userID, "mfa-push-token", pushTokenHash, []byte(pushToken))
	if err != nil {
		return PushDevice{}, "", err
	}
	var row dbgen.ListPushDevicesRow
	err = tx.QueryRow(ctx, `
		INSERT INTO auth.mfa_push_devices
		    (user_id, name, push_token, push_token_ct, push_token_nonce, push_token_hash,
		     platform, device_token, device_token_hash, encryption_version)
		VALUES ($1, $2, NULL, $3, $4, $5, $6, NULL, $7, 1)
		ON CONFLICT (user_id, push_token_hash) WHERE push_token_hash IS NOT NULL DO UPDATE SET
		    name = EXCLUDED.name,
		    push_token = NULL,
		    push_token_ct = EXCLUDED.push_token_ct,
		    push_token_nonce = EXCLUDED.push_token_nonce,
		    platform = EXCLUDED.platform,
		    device_token = NULL,
		    device_token_hash = EXCLUDED.device_token_hash,
		    encryption_version = 1,
		    last_seen_at = NOW()
		RETURNING id, user_id, name, platform, created_at, last_seen_at
	`, userID, name, ciphertext, nonce, pushTokenHash, platform, secretHash(tok)).Scan(
		&row.ID, &row.UserID, &row.Name, &row.Platform, &row.CreatedAt, &row.LastSeenAt,
	)
	if err != nil {
		return PushDevice{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	ch, err := s.q.WithTx(tx).InsertPushChallenge(ctx, dbgen.InsertPushChallengeParams{
		UserID:  userID,
		Action:  action,
		Context: ctxJSON,
	})
	if err != nil {
		return uuid.Nil, err
	}
	tokens, err := s.loadPushTokens(ctx, tx, userID)
	if err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := s.loadPushTokens(ctx, tx, userID); err != nil {
		return err
	}
	var deviceID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id FROM auth.mfa_push_devices
		WHERE user_id = $1 AND device_token_hash = $2
	`, userID, secretHash(deviceToken)).Scan(&deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrMFAPushUnauthorized
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

type storedPushToken struct {
	id         uuid.UUID
	legacy     *string
	ciphertext []byte
	nonce      []byte
	hash       *string
	device     *string
}

func (s *Service) loadPushTokens(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, push_token, push_token_ct, push_token_nonce, push_token_hash, device_token
		FROM auth.mfa_push_devices
		WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	var records []storedPushToken
	for rows.Next() {
		var record storedPushToken
		if err := rows.Scan(&record.id, &record.legacy, &record.ciphertext, &record.nonce, &record.hash, &record.device); err != nil {
			rows.Close()
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	tokens := make([]string, 0, len(records))
	for _, record := range records {
		if len(record.ciphertext) > 0 {
			if s.box == nil {
				return nil, errors.New("MFA secret encryption is unavailable")
			}
			if record.hash == nil || *record.hash == "" {
				return nil, errors.New("encrypted push device token has no lookup hash")
			}
			plain, err := s.box.Open(userID, "mfa-push-token", *record.hash, record.ciphertext, record.nonce)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, string(plain))
			continue
		}
		if record.legacy == nil {
			return nil, errors.New("push device token is missing")
		}
		if s.box == nil {
			return nil, errors.New("MFA secret encryption is unavailable")
		}
		pushTokenHash := secretHash(*record.legacy)
		ciphertext, nonce, err := s.box.Seal(userID, "mfa-push-token", pushTokenHash, []byte(*record.legacy))
		if err != nil {
			return nil, err
		}
		var deviceTokenHash *string
		if record.device != nil {
			hash := secretHash(*record.device)
			deviceTokenHash = &hash
		}
		if _, err := tx.Exec(ctx, `
			UPDATE auth.mfa_push_devices
			SET push_token = NULL, push_token_ct = $2, push_token_nonce = $3,
			    push_token_hash = $4, device_token = NULL, device_token_hash = $5,
			    encryption_version = 1
			WHERE id = $1 AND push_token_ct IS NULL
		`, record.id, ciphertext, nonce, pushTokenHash, deviceTokenHash); err != nil {
			return nil, err
		}
		tokens = append(tokens, *record.legacy)
	}
	return tokens, nil
}

func secretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
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
