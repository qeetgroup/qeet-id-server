//go:build integration

package mfa

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// codeAt returns the TOTP code steps 30-second steps from now. A step a code
// was accepted in can't be used again, so each use needs a later step.
func codeAt(t *testing.T, secret string, steps int) string {
	t.Helper()
	code, err := totp.Code(secret, time.Now().Add(time.Duration(steps)*30*time.Second))
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	return code
}

const testPassword = "Kx7mQ2vLp9Wz"

// sixDigits finds a sent one-time code.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// services returns the MFA service, sending codes through sender, and an
// authentication service that asks for its factors.
func services(t *testing.T, sender notifier.Sender) (*Service, *auth.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	mfaSvc := NewService(pool, "Qeet", sender)
	mfaSvc.SetCipher(box)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(mfaSvc)
	return mfaSvc, authSvc
}

// member creates a member of a new organization who signs in with
// testPassword.
func member(t *testing.T) (dbtest.Account, uuid.UUID) {
	t.Helper()
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	dbtest.SetPassword(t, a.ID, testPassword)
	return a, organization
}

// inTx runs fn in a transaction, committed when fn succeeds.
func inTx(t *testing.T, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// self is userID changing their own second factors, with no session.
func self(userID uuid.UUID) Caller {
	return Caller{Actor: audit.Actor{UserID: &userID, Type: "user"}}
}

// enrolTOTP sets up an authenticator app for a and returns its secret and
// recovery codes.
func enrolTOTP(t *testing.T, svc *Service, a dbtest.Account) (string, []string) {
	t.Helper()
	ctx := dbtest.Context(t)
	enrollment, err := svc.StartEnroll(ctx, a.ID, a.Email, self(a.ID))
	if err != nil {
		t.Fatalf("start enrolment: %v", err)
	}
	recovery, err := svc.ConfirmEnroll(ctx, a.ID, codeAt(t, enrollment.Secret, 0), self(a.ID))
	if err != nil {
		t.Fatalf("confirm enrolment: %v", err)
	}
	return enrollment.Secret, recovery
}

// challenge signs a in with testPassword and returns the second step's token.
func challenge(t *testing.T, authSvc *auth.Service, a dbtest.Account) string {
	t.Helper()
	res, err := authSvc.Login(dbtest.Context(t), auth.LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || !res.MFARequired || res.MFAToken == "" {
		t.Fatalf("sign in: %+v, %v; want a second-factor challenge", res, err)
	}
	return res.MFAToken
}

// phones is a fake Firebase Cloud Messaging: it records each sign-in
// request's challenge and answers UNREGISTERED for a push token containing
// "gone".
type phones struct {
	fcm        *fcmClient
	mu         sync.Mutex
	challenges []string
}

func newPhones(t *testing.T) *phones {
	p := &phones{}
	p.fcm, _ = testFCM(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = io.WriteString(w, `{"access_token":"ya29.test","expires_in":3600}`)
			return
		}
		var body struct {
			Message struct {
				Token string            `json:"token"`
				Data  map[string]string `json:"data"`
			} `json:"message"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Message.Data["type"] == pushPayloadType {
			p.mu.Lock()
			p.challenges = append(p.challenges, body.Message.Data["challenge_id"])
			p.mu.Unlock()
		}
		if strings.Contains(body.Message.Token, "gone") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`)
		}
	})
	return p
}

// pushServices returns MFA and authentication services that deliver push
// requests to Android phones through push.
func pushServices(t *testing.T, push *phones) (*Service, *auth.Service) {
	t.Helper()
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	mfaSvc.fcm = push.fcm
	return mfaSvc, authSvc
}

func (p *phones) sent() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.challenges...)
}
