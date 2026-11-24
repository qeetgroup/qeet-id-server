package mfa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const apnsDeviceToken = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

func pkcs8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// testAPNs returns an APNs client pointed at handler, and the key that signs its provider tokens.
func testAPNs(t *testing.T, handler http.HandlerFunc) (*apnsClient, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	c, err := newAPNsClient(APNsConfig{AuthKey: pkcs8PEM(t, key), KeyID: "KEY123", TeamID: "TEAM456", BundleID: "com.qeetgroup.qeetid"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.host = srv.URL
	return c, key
}

func TestAPNsSendsATimeSensitiveAlert(t *testing.T) {
	challenge := uuid.New()
	var got *http.Request
	var body []byte
	c, key := testAPNs(t, func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
	})
	if err := c.send(t.Context(), apnsDeviceToken, signInMessage(challenge, "sign_in")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got.URL.Path != "/3/device/"+apnsDeviceToken {
		t.Errorf("path = %s", got.URL.Path)
	}
	for header, want := range map[string]string{
		"apns-topic": "com.qeetgroup.qeetid", "apns-push-type": "alert", "apns-priority": "10", "apns-collapse-id": challenge.String(),
	} {
		if v := got.Header.Get(header); v != want {
			t.Errorf("%s = %q, want %q", header, v, want)
		}
	}
	// The provider token is an ES256 JWT from the team, naming the key.
	bearer := strings.TrimPrefix(got.Header.Get("Authorization"), "bearer ")
	tok, err := jwt.Parse(bearer, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("provider token: %v", err)
	}
	if tok.Header["kid"] != "KEY123" || tok.Claims.(jwt.MapClaims)["iss"] != "TEAM456" {
		t.Errorf("provider token kid/iss = %v / %v", tok.Header["kid"], tok.Claims.(jwt.MapClaims)["iss"])
	}
	var payload struct {
		Aps struct {
			Alert   struct{ Title, Body string } `json:"alert"`
			Level   string                       `json:"interruption-level"`
			Mutable int                          `json:"mutable-content"`
		} `json:"aps"`
		Type        string `json:"type"`
		ChallengeID string `json:"challenge_id"`
		Action      string `json:"action"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Aps.Alert.Title != pushAlertTitle || payload.Aps.Level != "time-sensitive" || payload.Aps.Mutable != 1 ||
		payload.Type != pushPayloadType || payload.ChallengeID != challenge.String() || payload.Action != "sign_in" {
		t.Errorf("payload = %+v", payload)
	}
}

func TestAPNsGoneMeansTheAppIsGone(t *testing.T) {
	c, _ := testAPNs(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = io.WriteString(w, `{"reason":"Unregistered"}`)
	})
	if err := c.send(t.Context(), apnsDeviceToken, signInMessage(uuid.New(), "sign_in")); !errors.Is(err, errPushDeviceGone) {
		t.Fatalf("err = %v, want errPushDeviceGone", err)
	}
}

func TestAPNsRefreshesAnExpiredProviderTokenOnce(t *testing.T) {
	var calls atomic.Int32
	c, _ := testAPNs(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"reason":"ExpiredProviderToken"}`)
		}
	})
	if err := c.send(t.Context(), apnsDeviceToken, signInMessage(uuid.New(), "sign_in")); err != nil || calls.Load() != 2 {
		t.Fatalf("err = %v after %d calls, want success on the second", err, calls.Load())
	}
}

func TestAPNsRefusesATokenThatIsNotHex(t *testing.T) {
	c, _ := testAPNs(t, func(http.ResponseWriter, *http.Request) { t.Error("nothing should be sent") })
	if err := c.send(t.Context(), "../../3/device/x", signInMessage(uuid.New(), "sign_in")); err == nil {
		t.Fatal("a non-hex token was sent")
	}
}

// testFCM returns an FCM client whose token exchange and send endpoints are handler, and the
// service account's key.
func testFCM(t *testing.T, handler http.HandlerFunc) (*fcmClient, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	sa, _ := json.Marshal(map[string]string{
		"project_id": "qeet-id-test", "client_email": "push@qeet-id-test.iam.gserviceaccount.com",
		"private_key": pkcs8PEM(t, key), "token_uri": srv.URL + "/token",
	})
	c, err := newFCMClient(FCMConfig{ServiceAccountJSON: string(sa)}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.sendURL = srv.URL + "/send"
	return c, key
}

func TestFCMSendsAHighPriorityDataMessage(t *testing.T) {
	challenge := uuid.New()
	var message map[string]any
	var key *rsa.PrivateKey // assigned below; the handler only runs once requests are sent
	c, k := testFCM(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			tok, err := jwt.Parse(r.PostForm.Get("assertion"), func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
				jwt.WithValidMethods([]string{"RS256"}))
			if err != nil || tok.Claims.(jwt.MapClaims)["scope"] != fcmScope {
				t.Errorf("assertion: %v %v", err, tok)
			}
			_, _ = io.WriteString(w, `{"access_token":"ya29.test","expires_in":3600}`)
		case "/send":
			if r.Header.Get("Authorization") != "Bearer ya29.test" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			_ = json.NewDecoder(r.Body).Decode(&message)
			_, _ = io.WriteString(w, `{"name":"projects/qeet-id-test/messages/1"}`)
		}
	})
	key = k
	if err := c.send(t.Context(), "fcm-registration-token", signInMessage(challenge, "sign_in")); err != nil {
		t.Fatalf("send: %v", err)
	}
	m := message["message"].(map[string]any)
	data := m["data"].(map[string]any)
	android := m["android"].(map[string]any)
	if m["token"] != "fcm-registration-token" || data["challenge_id"] != challenge.String() || data["type"] != pushPayloadType ||
		android["priority"] != "HIGH" || android["ttl"] != "120s" {
		t.Errorf("message = %v", m)
	}
	if _, hasNotification := m["notification"]; hasNotification {
		t.Error("a data message must not carry a notification block: the app writes its own")
	}
}

func TestFCMUnregisteredMeansTheAppIsGone(t *testing.T) {
	c, _ := testFCM(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = io.WriteString(w, `{"access_token":"ya29.test","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`)
	})
	if err := c.send(t.Context(), "stale-token", signInMessage(uuid.New(), "sign_in")); !errors.Is(err, errPushDeviceGone) {
		t.Fatalf("err = %v, want errPushDeviceGone", err)
	}
}

// TestDeliverPushRoutesByPlatform checks that a phone is sent to through its platform's
// service, APNs for iOS and FCM for Android, and that a phone whose service isn't configured
// is not sent to.
func TestDeliverPushRoutesByPlatform(t *testing.T) {
	var apns, fcm atomic.Int32
	apnsClient, _ := testAPNs(t, func(http.ResponseWriter, *http.Request) { apns.Add(1) })
	fcmClient, _ := testFCM(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = io.WriteString(w, `{"access_token":"ya29.test","expires_in":3600}`)
			return
		}
		fcm.Add(1)
	})
	s := &Service{apns: apnsClient, fcm: fcmClient}
	m := signInMessage(uuid.New(), "sign_in")
	for _, target := range []pushTarget{
		{token: apnsDeviceToken, platform: "ios"},
		{token: "fcm-registration-token", platform: "android"},
	} {
		if err := s.deliverPush(t.Context(), target, m); err != nil {
			t.Errorf("deliver %s: %v", target.platform, err)
		}
	}
	if apns.Load() != 1 || fcm.Load() != 1 {
		t.Errorf("sent apns/fcm = %d/%d, want 1/1", apns.Load(), fcm.Load())
	}
	if err := s.deliverPush(t.Context(), pushTarget{token: "fcm-registration-token", platform: "web"}, m); !errors.Is(err, errPushNotConfigured) {
		t.Errorf("an unknown platform: err = %v, want errPushNotConfigured", err)
	}
	bare := &Service{}
	if err := bare.deliverPush(t.Context(), pushTarget{token: apnsDeviceToken, platform: "ios"}, m); !errors.Is(err, errPushNotConfigured) {
		t.Errorf("unconfigured APNs: err = %v", err)
	}
	if bare.pushConfigured() || !s.pushConfigured() {
		t.Error("pushConfigured is wrong")
	}
}

func TestEnablingPushRefusesUnusableCredentials(t *testing.T) {
	s := &Service{}
	if err := s.enableAPNs(APNsConfig{AuthKey: "not a key", KeyID: "K", TeamID: "T", BundleID: "B"}); err == nil {
		t.Error("APNs accepted a key that is not PEM")
	}
	if err := s.enableFCM(FCMConfig{ServiceAccountJSON: `{"project_id":"p"}`}); err == nil {
		t.Error("FCM accepted a service account without a key")
	}
	if s.apns != nil || s.fcm != nil {
		t.Error("a refused service was enabled")
	}
}

// TestSignInPayloadsStayAsTheAppsExpect pins the sign-in request the native apps read, and
// checks a notice carries its own words: active, not time-sensitive, and its text in the
// Android data so the app can show it.
func TestSignInPayloadsStayAsTheAppsExpect(t *testing.T) {
	id := uuid.MustParse("6f1c2b8a-3d4e-4f5a-8b9c-0d1e2f3a4b5c")
	raw, err := apnsPayload(signInMessage(id, "sign_in"))
	if err != nil {
		t.Fatal(err)
	}
	var apns map[string]any
	_ = json.Unmarshal(raw, &apns)
	aps := apns["aps"].(map[string]any)
	if apns["type"] != pushPayloadType || apns["challenge_id"] != id.String() || apns["action"] != "sign_in" ||
		aps["interruption-level"] != "time-sensitive" || aps["thread-id"] != "sign-in" {
		t.Errorf("sign-in APNs payload %s", raw)
	}
	raw, _ = fcmPayload("token", signInMessage(id, "sign_in"))
	var fcm struct {
		Message struct {
			Data    map[string]string `json:"data"`
			Android map[string]any    `json:"android"`
		} `json:"message"`
	}
	_ = json.Unmarshal(raw, &fcm)
	if len(fcm.Message.Data) != 3 || fcm.Message.Data["type"] != pushPayloadType || fcm.Message.Data["challenge_id"] != id.String() ||
		fcm.Message.Android["ttl"] != "120s" || fcm.Message.Android["collapse_key"] != id.String() {
		t.Errorf("sign-in FCM payload %s", raw)
	}

	notice := pushMessage{kind: "access_request", collapseID: "r1", title: "Access request", body: "Arjun Rao asks for Finance",
		data: map[string]string{"kind": "access_request", "access_request_id": "r1"}, ttl: noticeTTL, thread: "access_request", textInData: true}
	raw, _ = apnsPayload(notice)
	apns = nil
	_ = json.Unmarshal(raw, &apns)
	aps = apns["aps"].(map[string]any)
	alert := aps["alert"].(map[string]any)
	if apns["type"] != "access_request" || apns["access_request_id"] != "r1" || aps["interruption-level"] != "active" || alert["body"] != "Arjun Rao asks for Finance" {
		t.Errorf("notice APNs payload %s", raw)
	}
	raw, _ = fcmPayload("token", notice)
	_ = json.Unmarshal(raw, &fcm)
	if fcm.Message.Data["title"] != "Access request" || fcm.Message.Data["body"] != "Arjun Rao asks for Finance" || fcm.Message.Android["ttl"] != "86400s" {
		t.Errorf("notice FCM payload %s", raw)
	}
}
