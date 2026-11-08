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

// PushDevice is a phone paired to approve sign-ins by push.
type PushDevice struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Platform   string    `json:"platform"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// PushChallenge is a sign-in or step-up waiting for approval on a paired
// phone.
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

// ListPushDevices returns the user's paired phones.
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

// RevokePushDevice unpairs one of the user's phones.
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

// Push requests are bounded so a person isn't worn down into approving one:
// a few in ten minutes, and none for the rest of an hour in which they denied
// several.
const (
	maxPushPer10Minutes   = 5
	maxPushDenialsPerHour = 3
)

// CreatePushChallenge records a pending challenge, sends it to every phone
// the user has linked, and returns its ID and the number the phone must send
// back to approve it, shown where it was asked for. It fails with
// ErrMFAPushLimited past the bounds above, and with ErrMFAPushDeliveryFailed,
// closing the challenge, when no phone accepted it. A phone whose push service
// has no credentials here is not a failure: like every phone when no push
// service is configured, it finds the request when the app next opens.
func (s *Service) CreatePushChallenge(ctx context.Context, userID uuid.UUID, action string, pctx PushChallengeContext) (uuid.UUID, int, error) {
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
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mfa-push:' || $1::text, 0))`, userID); err != nil {
		return uuid.Nil, 0, err
	}
	recent, err := s.q.WithTx(tx).RecentPushChallenges(ctx, userID)
	if err != nil {
		return uuid.Nil, 0, err
	}
	if recent.Sent >= maxPushPer10Minutes || recent.Denied >= maxPushDenialsPerHour {
		return uuid.Nil, 0, errs.ErrMFAPushLimited
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
		err := s.deliverPush(ctx, t, ch.ID, action)
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
		_, _ = s.pool.Exec(ctx, `
			UPDATE auth.mfa_push_challenges SET status = 'expired', expires_at = LEAST(expires_at, NOW())
			WHERE id = $1 AND status = 'pending'
		`, ch.ID)
		return uuid.Nil, 0, errs.ErrMFAPushDeliveryFailed
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
		return errs.ErrMFAPushNumberMismatch
	}
	return nil
}

type storedPushToken struct {
	id         uuid.UUID
	platform   string
	legacy     *string
	ciphertext []byte
	nonce      []byte
	hash       *string
	device     *string
}

func (s *Service) loadPushTokens(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]pushTarget, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, platform, push_token, push_token_ct, push_token_nonce, push_token_hash, device_token
		FROM auth.mfa_push_devices
		WHERE user_id = $1 AND device_token_expires_at > NOW()
	`, userID)
	if err != nil {
		return nil, err
	}
	var records []storedPushToken
	for rows.Next() {
		var record storedPushToken
		if err := rows.Scan(&record.id, &record.platform, &record.legacy, &record.ciphertext, &record.nonce, &record.hash, &record.device); err != nil {
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

	tokens := make([]pushTarget, 0, len(records))
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
			tokens = append(tokens, pushTarget{token: string(plain), platform: record.platform})
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
		tokens = append(tokens, pushTarget{token: *record.legacy, platform: record.platform})
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

	resp, err := http.DefaultClient.Do(req) //nolint:forbidigo // operator-configured Expo endpoint, not tenant-controlled
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
	// A linked phone tells the server its new push token when the platform rotates it.
	r.Post("/mfa/push/devices/{id}/push-token", h.updatePushToken)
	// A linked phone asks for requests waiting on it, for when a push was late or lost.
	r.Post("/mfa/push/devices/{id}/pending", h.listPendingPushChallenges)
	// The mobile app links the phone with a pairing code, holding no session.
	if h.PairingThrottle != nil {
		r.With(h.PairingThrottle).Post("/mfa/push/pairing/claim", h.claimPushPairing)
	} else {
		r.Post("/mfa/push/pairing/claim", h.claimPushPairing)
	}
}

// MountAdmin mounts an administrator's view of a member's linked phones, in
// the administrator's own organisation (user.read / user.credentials).
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
	h.Service.tellPhoneLinked(r.Context(), *p.UserID)
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
	h.Service.tellPhoneUnlinked(r.Context(), *p.UserID)
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
	h.Service.tellPhoneUnlinked(r.Context(), in.UserID)
	w.WriteHeader(http.StatusNoContent)
}

type updatePushTokenInput struct {
	UserID      uuid.UUID `json:"user_id"`
	DeviceToken string    `json:"device_token"`
	PushToken   string    `json:"push_token"`
}

// maxPushTokenLength bounds a push token: APNs tokens are 64 hex characters and FCM
// registration tokens a few hundred.
const maxPushTokenLength = 4096

// updatePushToken → POST /v1/mfa/push/devices/{id}/push-token: a linked phone replaces the
// push token its platform rotated, proving it is that device with its current (unexpired)
// device credential. The credential, the link's expiry and the platform are unchanged.
func (h *Handler) updatePushToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in updatePushTokenInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.DeviceToken == "" || in.UserID == uuid.Nil || in.PushToken == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("user_id, device_token and push_token required"))
		return
	}
	if len(in.PushToken) > maxPushTokenLength {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("push_token is too long"))
		return
	}
	if err := h.Service.UpdatePushToken(r.Context(), id, in.UserID, in.DeviceToken, in.PushToken); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listPendingPushChallenges → POST /v1/mfa/push/devices/{id}/pending: a linked phone asks for
// the sign-in requests waiting on its account, proving it is that device with its current
// device credential (sent in the body, never in a URL). The app calls it when it comes to the
// foreground, so a request whose push was delayed or dropped can still be answered.
func (h *Handler) listPendingPushChallenges(w http.ResponseWriter, r *http.Request) {
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
	var found uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM auth.mfa_push_devices
		WHERE id = $1 AND user_id = $2 AND device_token_hash = $3 AND device_token_expires_at > NOW()
	`, deviceID, userID, secretHash(deviceToken)).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrMFAPushUnauthorized
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, action, context, status, expires_at, created_at
		FROM auth.mfa_push_challenges
		WHERE user_id = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT $2
	`, userID, maxPendingPushChallenges)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PushChallenge{}
	for rows.Next() {
		var c PushChallenge
		if err := rows.Scan(&c.ID, &c.UserID, &c.Action, &c.Context, &c.Status, &c.ExpiresAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdatePushToken stores a phone's new push token, sealed like the one it replaces. The phone
// proves itself with its device credential, which must not have expired. Another of the
// user's links already holding the same token (the same app, linked before) is removed, so the
// phone is sent each request once. ErrMFAPushUnauthorized when the device or credential does
// not match.
func (s *Service) UpdatePushToken(ctx context.Context, deviceID, userID uuid.UUID, deviceToken, pushToken string) error {
	if s.box == nil {
		return errs.ErrInternalServer.WithDetail("MFA secret encryption is unavailable")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var found uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id FROM auth.mfa_push_devices
		WHERE id = $1 AND user_id = $2 AND device_token_hash = $3 AND device_token_expires_at > NOW()
		FOR UPDATE
	`, deviceID, userID, secretHash(deviceToken)).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrMFAPushUnauthorized
	}
	if err != nil {
		return err
	}
	pushTokenHash := secretHash(pushToken)
	ciphertext, nonce, err := s.box.Seal(userID, "mfa-push-token", pushTokenHash, []byte(pushToken))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM auth.mfa_push_devices WHERE user_id = $1 AND push_token_hash = $2 AND id <> $3
	`, userID, pushTokenHash, deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_push_devices
		SET push_token = NULL, push_token_ct = $2, push_token_nonce = $3, push_token_hash = $4, encryption_version = 1
		WHERE id = $1
	`, deviceID, ciphertext, nonce, pushTokenHash); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
		actorID, actorType = audit.ActorOf(r).Identity()
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
	Number      int       `json:"number"` // the number shown where the request was asked for
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
	if err := h.Service.RespondToPushChallenge(r.Context(), id, in.UserID, in.DeviceToken, in.Approved, in.Number); err != nil {
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
