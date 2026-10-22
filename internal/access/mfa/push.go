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
	"log/slog"
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

// PushChallengeContext is shown in the app so the user can decide whether to
// approve. SessionID is the session a step-up request was raised for; only
// that session is stepped up when it is approved.
type PushChallengeContext struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Location  string `json:"location,omitempty"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"session_id,omitempty"`
}

// ── Service methods ───────────────────────────────────────────────────────────

// pushDeviceTTL is how long a linked phone's device credential works after it
// was last linked; linking again renews it.
const pushDeviceTTL = 180 * 24 * time.Hour

// RegisterPushDevice upserts a device push token and returns the device record
// plus a one-time device_token the app must persist for future challenge-respond
// calls. On re-registration of the same push_token the device_token is rotated.
func (s *Service) RegisterPushDevice(ctx context.Context, userID uuid.UUID, name, pushToken, platform string) (PushDevice, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PushDevice{}, "", err
	}
	defer tx.Rollback(ctx)
	d, tok, err := s.registerPushDeviceTx(ctx, tx, userID, name, pushToken, platform)
	if err != nil {
		return PushDevice{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return PushDevice{}, "", err
	}
	return d, tok, nil
}

// registerPushDeviceTx is RegisterPushDevice inside the caller's transaction.
func (s *Service) registerPushDeviceTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, name, pushToken, platform string) (PushDevice, string, error) {
	tok, err := randomHex(32)
	if err != nil {
		return PushDevice{}, "", err
	}
	if s.box == nil {
		return PushDevice{}, "", errs.ErrInternalServer.WithDetail("MFA secret encryption is unavailable")
	}
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
		     platform, device_token, device_token_hash, encryption_version, device_token_expires_at)
		VALUES ($1, $2, NULL, $3, $4, $5, $6, NULL, $7, 1, NOW() + make_interval(secs => $8))
		ON CONFLICT (user_id, push_token_hash) WHERE push_token_hash IS NOT NULL DO UPDATE SET
		    name = EXCLUDED.name,
		    push_token = NULL,
		    push_token_ct = EXCLUDED.push_token_ct,
		    push_token_nonce = EXCLUDED.push_token_nonce,
		    platform = EXCLUDED.platform,
		    device_token = NULL,
		    device_token_hash = EXCLUDED.device_token_hash,
		    encryption_version = 1,
		    device_token_expires_at = EXCLUDED.device_token_expires_at,
		    last_seen_at = NOW()
		RETURNING id, user_id, name, platform, created_at, last_seen_at
	`, userID, name, ciphertext, nonce, pushTokenHash, platform, secretHash(tok), pushDeviceTTL.Seconds()).Scan(
		&row.ID, &row.UserID, &row.Name, &row.Platform, &row.CreatedAt, &row.LastSeenAt,
	)
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

// CreatePushChallenge records a pending challenge, sends it to every phone
// the user has linked, and returns its ID. It fails with
// ErrMFAPushDeliveryFailed, closing the challenge, when no phone accepted it.
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
	if s.pushURL == "" {
		return ch.ID, nil // push delivery not configured
	}
	delivered := 0
	for _, tok := range tokens {
		err := s.sendExpoPush(ctx, tok, ch.ID, action)
		switch {
		case err == nil:
			delivered++
		case errors.Is(err, errPushDeviceGone):
			// The app was removed from that phone: stop sending to it.
			s.retirePushToken(ctx, userID, tok)
			slog.Info("push device no longer registered; retired", "challenge_id", ch.ID, "device_ref", pushTokenRef(tok))
		default:
			slog.Warn("push delivery failed", "challenge_id", ch.ID, "device_ref", pushTokenRef(tok), "err", err)
		}
	}
	if len(tokens) > 0 && delivered == 0 {
		// Nothing can answer it: close it now rather than leave the sign-in
		// waiting out its two minutes.
		_, _ = s.pool.Exec(ctx, `
			UPDATE auth.mfa_push_challenges SET status = 'expired', expires_at = LEAST(expires_at, NOW())
			WHERE id = $1 AND status = 'pending'
		`, ch.ID)
		return uuid.Nil, errs.ErrMFAPushDeliveryFailed
	}
	return ch.ID, nil
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
		WHERE user_id = $1 AND device_token_hash = $2 AND device_token_expires_at > NOW()
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
		WHERE user_id = $1 AND device_token_expires_at > NOW()
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

// Approval requests reach a phone through Expo's push service, which hands
// them to Apple's or Google's.
const (
	pushSendTimeout = 10 * time.Second // one call to the push service; a sign-in waits on it
	pushRequestTTL  = 2 * time.Minute  // delivery retries, as long as a challenge can be answered
	pushChannelID   = "push-mfa"       // the app's highest-importance Android notification channel
)

// errPushDeviceGone means the push service reports the app is not installed on
// that phone (DeviceNotRegistered).
var errPushDeviceGone = errors.New("push device not registered")

// expoPushMessage is one message to the push service. Priority "high" wakes an
// idle Android phone; "normal" can wait for it.
type expoPushMessage struct {
	To        string         `json:"to"`
	Title     string         `json:"title"`
	Body      string         `json:"body"`
	Data      map[string]any `json:"data"`
	Priority  string         `json:"priority"`
	TTL       int            `json:"ttl"`
	ChannelID string         `json:"channelId"`
}

// expoPushTicket is the push service's answer for one message: "ok", or
// "error" with a machine-readable reason in details.error.
type expoPushTicket struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Details struct {
		Error string `json:"error"`
	} `json:"details"`
}

// SetExpoAccessToken sets the Expo access token sent with every push, which
// Expo requires once enhanced push security is turned on for the project.
func (s *Service) SetExpoAccessToken(token string) { s.pushAccessToken = token }

// pushTokenRef names a push token in logs without revealing it.
func pushTokenRef(pushToken string) string { return secretHash(pushToken)[:12] }

// sendExpoPush sends one approval request to one phone and reads the push
// service's answer: a refused message is an error (errPushDeviceGone when the
// app is gone from the phone), not a silent success.
func (s *Service) sendExpoPush(ctx context.Context, pushToken string, challengeID uuid.UUID, action string) error {
	msg := expoPushMessage{
		To:    pushToken,
		Title: fmt.Sprintf("Sign-in request: %s", action),
		Body:  "Tap to approve or deny this request.",
		Data: map[string]any{
			"challenge_id": challengeID.String(),
			"action":       action,
		},
		Priority:  "high",
		TTL:       int(pushRequestTTL.Seconds()),
		ChannelID: pushChannelID,
	}
	payload, err := json.Marshal([]expoPushMessage{msg})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, pushSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.pushURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if s.pushAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.pushAccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	// The service's messages can quote the token back; it is kept encrypted,
	// so it must not reach a log.
	redact := func(text string) string { return strings.ReplaceAll(text, pushToken, "[push token]") }
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("push service answered %d: %.200s", resp.StatusCode, redact(string(body)))
	}
	var out struct {
		Data []expoPushTicket `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("push service answer: %w", err)
	}
	if len(out.Data) != 1 {
		return fmt.Errorf("push service answered %d tickets for one message", len(out.Data))
	}
	if t := out.Data[0]; t.Status != "ok" {
		if t.Details.Error == "DeviceNotRegistered" {
			return errPushDeviceGone
		}
		return fmt.Errorf("push service refused the message: %s (%s)", t.Details.Error, redact(t.Message))
	}
	return nil
}

// retirePushToken stops sending to a phone the app is gone from: its device
// credential is expired, so it is neither sent requests nor offered at
// sign-in. Linking the phone again renews it. Best effort.
func (s *Service) retirePushToken(ctx context.Context, userID uuid.UUID, pushToken string) {
	_, _ = s.pool.Exec(ctx, `
		UPDATE auth.mfa_push_devices SET device_token_expires_at = NOW()
		WHERE user_id = $1 AND push_token_hash = $2 AND device_token_expires_at > NOW()
	`, userID, secretHash(pushToken))
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// MountPublic mounts the unauthenticated challenge endpoints (polled by the
// browser waiting for approval, and called by the mobile app responding to a
// push).
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/mfa/push/challenges/{id}", h.getPushChallenge)
	r.Post("/mfa/push/challenges/{id}/respond", h.respondToPushChallenge)
	// A linked phone removes itself with its own device credential: the app
	// holds no signed-in session to call the authenticated route with.
	r.Post("/mfa/push/devices/{id}/unlink", h.unlinkPushDevice)
	// The mobile app links the phone with a pairing code, holding no session.
	if h.PairingThrottle != nil {
		r.With(h.PairingThrottle).Post("/mfa/push/pairing/claim", h.claimPushPairing)
	} else {
		r.Post("/mfa/push/pairing/claim", h.claimPushPairing)
	}
}

// MountAdmin mounts an administrator's view of a member's linked phones, in
// the administrator's own organisation (user.read / user.write).
func (h *Handler) MountAdmin(r chi.Router) {
	r.Get("/users/{id}/push-devices", h.listMemberPushDevices)
	r.Delete("/users/{id}/push-devices/{deviceID}", h.revokeMemberPushDevice)
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
	h.Service.auditPushDevice(r, p.TenantID, *p.UserID, deviceID, "mfa.push_device_revoked")
	w.WriteHeader(http.StatusNoContent)
}

type unlinkPushDeviceInput struct {
	UserID      uuid.UUID `json:"user_id"`
	DeviceToken string    `json:"device_token"`
}

// unlinkPushDevice → POST /v1/mfa/push/devices/{id}/unlink: a phone removes
// itself, proving it is that device with the credential it was given when
// linked (even one past its expiry: removing itself grants nothing).
func (h *Handler) unlinkPushDevice(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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
	n, err := h.Service.q.DeletePushDeviceByCredential(r.Context(), dbgen.DeletePushDeviceByCredentialParams{
		ID: id, UserID: in.UserID, DeviceTokenHash: ptr(secretHash(in.DeviceToken)),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if n == 0 {
		httpx.WriteError(w, r, errs.ErrMFAPushUnauthorized)
		return
	}
	h.Service.auditPushDevice(r, nil, in.UserID, id, "mfa.push_device_unlinked")
	w.WriteHeader(http.StatusNoContent)
}

// memberInScope returns the member a route names, refused as not found unless
// they belong to the caller's organisation.
func (h *Handler) memberInScope(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid id")
	}
	member, err := h.Service.q.IsTenantMember(r.Context(), dbgen.IsTenantMemberParams{UserID: userID, TenantID: tenantID})
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if !member {
		return uuid.Nil, uuid.Nil, errs.ErrNotFound
	}
	return userID, tenantID, nil
}

// listMemberPushDevices → GET /v1/users/{id}/push-devices.
func (h *Handler) listMemberPushDevices(w http.ResponseWriter, r *http.Request) {
	userID, _, err := h.memberInScope(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListPushDevices(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// revokeMemberPushDevice → DELETE /v1/users/{id}/push-devices/{deviceID}: an
// administrator disconnects a member's lost phone.
func (h *Handler) revokeMemberPushDevice(w http.ResponseWriter, r *http.Request) {
	userID, tenantID, err := h.memberInScope(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	deviceID, err := uuid.Parse(chi.URLParam(r, "deviceID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid deviceID"))
		return
	}
	if err := h.Service.RevokePushDevice(r.Context(), userID, deviceID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.auditPushDevice(r, &tenantID, userID, deviceID, "mfa.push_device_revoked")
	w.WriteHeader(http.StatusNoContent)
}

// auditPushDevice records a linked phone removed, best effort: the removal
// stands either way.
func (s *Service) auditPushDevice(r *http.Request, tenantID *uuid.UUID, owner, deviceID uuid.UUID, action string) {
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	actorID, actorType := &owner, "device"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID, actorType = auditActor(r)
	}
	if audit.Record(ctx, tx, audit.Event{
		TenantID: tenantID, ActorUserID: actorID, ActorType: actorType,
		Action: action, ResourceType: "push_device", ResourceID: &deviceID,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"user_id": owner},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

func ptr[T any](v T) *T { return &v }

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
