package mfa

// Push delivery: Apple Push Notification service for the iOS app and Firebase Cloud Messaging
// for the Android app. Each is optional; a phone whose service isn't configured is simply not
// sent to (and logged).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
)

// pushTarget is one linked phone to send a request to: its push token, and the platform it
// registered with, which picks the service for a native token.
type pushTarget struct {
	token    string
	platform string
}

// errPushNotConfigured: the phone's push service has no credentials on this server.
var errPushNotConfigured = errors.New("push service for this phone is not configured")

// The notification a native app shows, written here so both platforms read the same.
const (
	pushPayloadType = "sign_in_request"
	pushAlertTitle  = "Sign-in request"
	pushAlertBody   = "Someone is signing in to your Qeet ID account. Tap to review."
)

// pushMessage is one notification for a linked phone: a sign-in request, or a notice about
// something waiting for its person (an access request to answer).
type pushMessage struct {
	kind          string            // the payload's "type"
	collapseID    string            // a newer message with the same id replaces this one
	title, body   string            // what the phone shows
	data          map[string]string // besides "type"
	ttl           time.Duration     // how long the service keeps trying
	timeSensitive bool              // iOS: break through Focus
	thread        string            // iOS: how the phone groups them
	textInData    bool              // Android: the app shows title and body from the data
}

// signInMessage is a sign-in or step-up request, exactly as the apps expect it.
func signInMessage(challengeID uuid.UUID, action string) pushMessage {
	return pushMessage{
		kind: pushPayloadType, collapseID: challengeID.String(),
		title: pushAlertTitle, body: pushAlertBody,
		data:          map[string]string{"challenge_id": challengeID.String(), "action": action},
		ttl:           pushRequestTTL,
		timeSensitive: true,
		thread:        "sign-in",
	}
}

// pushConfigured reports whether any push service can deliver.
func (s *Service) pushConfigured() bool {
	return s.apns != nil || s.fcm != nil
}

// deliverPush sends m to one phone through the service of its platform: APNs or FCM.
func (s *Service) deliverPush(ctx context.Context, t pushTarget, m pushMessage) error {
	switch t.platform {
	case "ios":
		if s.apns == nil {
			return errPushNotConfigured
		}
		return s.apns.send(ctx, t.token, m)
	case "android":
		if s.fcm == nil {
			return errPushNotConfigured
		}
		return s.fcm.send(ctx, t.token, m)
	default:
		return errPushNotConfigured
	}
}

// pushHTTPClient is the client for the push services: operator-configured endpoints, never
// organization-controlled, with a bound on every call because a sign-in waits on it.
func pushHTTPClient() *http.Client {
	return &http.Client{Timeout: pushSendTimeout}
}

// ── APNs ──────────────────────────────────────────────────────────────────────

// APNsConfig is the token-based (.p8 key) connection to Apple Push Notification service.
type APNsConfig struct {
	AuthKey  string // the .p8 key's PEM text
	KeyID    string
	TeamID   string
	BundleID string // the app's bundle ID, sent as apns-topic
	Sandbox  bool   // development builds: api.sandbox.push.apple.com
}

// enableAPNs turns on delivery to the iOS app, failing on a key or setting
// that can't work.
func (s *Service) enableAPNs(cfg APNsConfig) error {
	c, err := newAPNsClient(cfg, pushHTTPClient())
	if err != nil {
		return err
	}
	s.apns = c
	return nil
}

type apnsClient struct {
	cfg  APNsConfig
	key  *ecdsa.PrivateKey
	host string
	http *http.Client
	now  func() time.Time

	mu     sync.Mutex
	bearer string
	issued time.Time
}

// apnsTokenLifetime: Apple accepts a provider token for an hour and refuses one refreshed more
// than every 20 minutes, so one is reused for 50.
const apnsTokenLifetime = 50 * time.Minute

func newAPNsClient(cfg APNsConfig, httpClient *http.Client) (*apnsClient, error) {
	if cfg.KeyID == "" || cfg.TeamID == "" || cfg.BundleID == "" {
		return nil, errors.New("APNs needs APNS_KEY_ID, APNS_TEAM_ID and APNS_BUNDLE_ID")
	}
	block, _ := pem.Decode([]byte(cfg.AuthKey))
	if block == nil {
		return nil, errors.New("APNs auth key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("APNs auth key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("APNs auth key is not an EC key")
	}
	host := "https://api.push.apple.com"
	if cfg.Sandbox {
		host = "https://api.sandbox.push.apple.com"
	}
	return &apnsClient{cfg: cfg, key: key, host: host, http: httpClient, now: time.Now}, nil
}

func (c *apnsClient) providerToken(refresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !refresh && c.bearer != "" && now.Sub(c.issued) < apnsTokenLifetime {
		return c.bearer, nil
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": c.cfg.TeamID, "iat": now.Unix()})
	tok.Header["kid"] = c.cfg.KeyID
	signed, err := tok.SignedString(c.key)
	if err != nil {
		return "", err
	}
	c.bearer, c.issued = signed, now
	return signed, nil
}

// apnsPayload is the alert the iOS app shows; its Notification Service Extension may add detail.
func apnsPayload(m pushMessage) ([]byte, error) {
	level := "active"
	if m.timeSensitive {
		level = "time-sensitive"
	}
	out := map[string]any{
		"aps": map[string]any{
			"alert":              map[string]string{"title": m.title, "body": m.body},
			"sound":              "default",
			"interruption-level": level,
			"mutable-content":    1,
			"thread-id":          m.thread,
		},
		"type": m.kind,
	}
	for k, v := range m.data {
		out[k] = v
	}
	return json.Marshal(out)
}

func (c *apnsClient) send(ctx context.Context, deviceToken string, m pushMessage) error {
	if _, err := hex.DecodeString(deviceToken); err != nil || deviceToken == "" {
		return errors.New("APNs device token is not hex")
	}
	payload, err := apnsPayload(m)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		bearer, err := c.providerToken(attempt > 0)
		if err != nil {
			return err
		}
		status, reason, err := c.post(ctx, deviceToken, bearer, m, payload)
		if err != nil {
			return err
		}
		switch {
		case status == http.StatusOK:
			return nil
		case status == http.StatusGone:
			return errPushDeviceGone // the app is gone from the phone
		case status == http.StatusForbidden && reason == "ExpiredProviderToken" && attempt == 0:
			continue // refresh the provider token once
		default:
			return fmt.Errorf("APNs answered %d: %s", status, reason)
		}
	}
}

func (c *apnsClient) post(ctx context.Context, deviceToken, bearer string, m pushMessage, payload []byte) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, pushSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+"/3/device/"+deviceToken, bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apns-topic", c.cfg.BundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("apns-expiration", fmt.Sprint(c.now().Add(m.ttl).Unix()))
	req.Header.Set("apns-collapse-id", m.collapseID)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if err != nil {
		return 0, "", err
	}
	var out struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out.Reason, nil
}

// ── FCM ───────────────────────────────────────────────────────────────────────

// FCMConfig is the Firebase project's service account, which signs the OAuth exchange for the
// FCM HTTP v1 API.
type FCMConfig struct {
	ServiceAccountJSON string
}

// enableFCM turns on delivery to the Android app, failing on an unusable
// account.
func (s *Service) enableFCM(cfg FCMConfig) error {
	c, err := newFCMClient(cfg, pushHTTPClient())
	if err != nil {
		return err
	}
	s.fcm = c
	return nil
}

type fcmClient struct {
	projectID   string
	clientEmail string
	tokenURI    string
	sendURL     string
	key         *rsa.PrivateKey
	http        *http.Client
	now         func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

func newFCMClient(cfg FCMConfig, httpClient *http.Client) (*fcmClient, error) {
	var sa struct {
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(cfg.ServiceAccountJSON), &sa); err != nil {
		return nil, fmt.Errorf("FCM service account: %w", err)
	}
	if sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("FCM service account needs project_id, client_email and private_key")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("FCM private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("FCM private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("FCM private key is not an RSA key")
	}
	return &fcmClient{
		projectID: sa.ProjectID, clientEmail: sa.ClientEmail, tokenURI: sa.TokenURI, key: key,
		sendURL: "https://fcm.googleapis.com/v1/projects/" + url.PathEscape(sa.ProjectID) + "/messages:send",
		http:    httpClient, now: time.Now,
	}, nil
}

// accessToken returns an OAuth token for FCM, exchanged with a signed assertion and reused
// until five minutes before it expires.
func (c *fcmClient) accessToken(ctx context.Context, refresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !refresh && c.access != "" && now.Before(c.expires.Add(-5*time.Minute)) {
		return c.access, nil
	}
	assertion, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": c.clientEmail, "scope": fcmScope, "aud": c.tokenURI,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}).SignedString(c.key)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	ctx, cancel := context.WithTimeout(ctx, pushSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("FCM token exchange answered %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("FCM token exchange returned no access token")
	}
	c.access, c.expires = out.AccessToken, now.Add(time.Duration(out.ExpiresIn)*time.Second)
	return c.access, nil
}

// fcmPayload is a data message: the Android app writes the notification itself, on its
// high-importance channel, so it can open the request directly.
func fcmPayload(token string, m pushMessage) ([]byte, error) {
	data := map[string]string{"type": m.kind}
	for k, v := range m.data {
		data[k] = v
	}
	if m.textInData {
		data["title"], data["body"] = m.title, m.body
	}
	return json.Marshal(map[string]any{"message": map[string]any{
		"token": token,
		"data":  data,
		"android": map[string]any{
			"priority":     "HIGH",
			"ttl":          fmt.Sprintf("%ds", int(m.ttl.Seconds())),
			"collapse_key": m.collapseID,
		},
	}})
}

func (c *fcmClient) send(ctx context.Context, token string, m pushMessage) error {
	payload, err := fcmPayload(token, m)
	if err != nil {
		return err
	}
	// The service's messages can quote the token back; it is kept encrypted, so it must not reach a log.
	redact := func(text string) string { return strings.ReplaceAll(text, token, "[push token]") }
	for attempt := 0; ; attempt++ {
		access, err := c.accessToken(ctx, attempt > 0)
		if err != nil {
			return err
		}
		status, body, err := c.post(ctx, access, payload)
		if err != nil {
			return err
		}
		switch {
		case status/100 == 2:
			return nil
		case status == http.StatusUnauthorized && attempt == 0:
			continue // refresh the access token once
		case fcmUnregistered(status, body):
			return errPushDeviceGone
		default:
			return fmt.Errorf("FCM answered %d: %.200s", status, redact(string(body)))
		}
	}
}

func (c *fcmClient) post(ctx context.Context, access string, payload []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, pushSendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sendURL, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, body, err
}

// fcmUnregistered reports FCM's answer for a token the app no longer holds: UNREGISTERED in
// the error details (404), as the HTTP v1 API documents.
func fcmUnregistered(status int, body []byte) bool {
	if status != http.StatusNotFound && status != http.StatusBadRequest {
		return false
	}
	var out struct {
		Error struct {
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &out) != nil {
		return false
	}
	for _, d := range out.Error.Details {
		if d.ErrorCode == "UNREGISTERED" {
			return true
		}
	}
	return false
}

// noticeTTL is how long the push services keep trying to deliver a notice.
const noticeTTL = 24 * time.Hour

// NotifyPhones tells userID's linked phones about something waiting for them, such as an access
// request to answer: an alert on iOS, a data message the Android app shows. data names it ("kind",
// and its id as "<kind>_id"); the phone opens it from there. Best effort, after the action that
// caused it: a failure is logged, and a phone its service says is gone is retired.
func (s *Service) NotifyPhones(ctx context.Context, userID uuid.UUID, title, body string, data map[string]string) {
	if s.apns == nil && s.fcm == nil {
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		slog.WarnContext(ctx, "phone notice: reading devices", "err", err)
		return
	}
	tokens, err := s.loadPushTokens(ctx, tx, userID)
	_ = tx.Rollback(ctx)
	if err != nil {
		slog.WarnContext(ctx, "phone notice: reading devices", "err", err)
		return
	}
	kind := data["kind"]
	if kind == "" {
		kind = "notice"
	}
	collapse := data[kind+"_id"]
	if collapse == "" {
		collapse = uuid.NewString()
	}
	m := pushMessage{kind: kind, collapseID: collapse, title: title, body: body, data: data,
		ttl: noticeTTL, thread: kind, textInData: true}
	for _, t := range tokens {
		switch err := s.deliverPush(ctx, t, m); {
		case err == nil, errors.Is(err, errPushNotConfigured):
		case errors.Is(err, errPushDeviceGone):
			s.retirePushToken(ctx, userID, t.token)
		default:
			slog.WarnContext(ctx, "phone notice: delivery failed", "kind", kind, "platform", t.platform,
				"device_ref", pushTokenRef(t.token), "err", err)
		}
	}
}

// Approval requests reach a phone through Apple's or Google's push service
// (pushnative.go).
const (
	pushSendTimeout = 10 * time.Second // one call to the push service; a sign-in waits on it
	pushRequestTTL  = 2 * time.Minute  // delivery retries, as long as a challenge can be answered
)

// errPushDeviceGone means the push service reports the app is not installed on
// that phone.
var errPushDeviceGone = errors.New("push device not registered")

// pushTokenRef names a push token in logs without revealing it.
func pushTokenRef(pushToken string) string { return secretHash(pushToken)[:12] }

// retirePushToken stops sending to a phone the app is gone from: its device
// credential is expired, so it is neither sent requests nor offered at
// sign-in. Linking the phone again renews it. Best effort.
func (s *Service) retirePushToken(ctx context.Context, userID uuid.UUID, pushToken string) {
	_ = s.q.RetirePushToken(ctx, dbgen.RetirePushTokenParams{UserID: userID, PushTokenHash: secretHash(pushToken)})
}
