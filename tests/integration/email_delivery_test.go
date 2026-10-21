//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

const (
	sesTopic   = "arn:aws:sns:ap-south-2:123456789012:qeet-id-ses-events"
	sesCertURL = "https://sns.ap-south-2.amazonaws.com/SimpleNotificationService-it.pem"
)

// fakeSES accepts every email and names it the way SES does.
type fakeSES struct {
	prefix string
	sent   int
}

func (f *fakeSES) Send(ctx context.Context, m notifier.Message) error {
	_, err := f.SendID(ctx, m)
	return err
}

func (f *fakeSES) SendID(context.Context, notifier.Message) (string, error) {
	f.sent++
	return fmt.Sprintf("%s-%d", f.prefix, f.sent), nil
}

// snsKey signs SNS messages, its certificate served at sesCertURL.
type snsKey struct {
	key  *rsa.PrivateKey
	cert []byte
}

func (k *snsKey) RoundTrip(r *http.Request) (*http.Response, error) {
	body := []byte("ok")
	if r.URL.String() == sesCertURL {
		body = k.cert
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
}

func newSNSKey(t *testing.T) *snsKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "sns"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &snsKey{key: key, cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// notification is a signed SNS Notification carrying one SES event.
func (k *snsKey) notification(t *testing.T, event map[string]any) []byte {
	t.Helper()
	msg, _ := json.Marshal(event)
	m := map[string]string{
		"Type": "Notification", "MessageId": uuid.NewString(), "TopicArn": sesTopic, "Message": string(msg),
		"Timestamp": time.Now().UTC().Format(time.RFC3339), "SignatureVersion": "2", "SigningCertURL": sesCertURL,
	}
	canonical := ""
	for _, key := range []string{"Message", "MessageId", "Timestamp", "TopicArn", "Type"} {
		canonical += key + "\n" + m[key] + "\n"
	}
	sum := sha256.Sum256([]byte(canonical))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	m["Signature"] = base64.StdEncoding.EncodeToString(sig)
	body, _ := json.Marshal(m)
	return body
}

func bounce(id, kind, address string) map[string]any {
	return map[string]any{"eventType": "Bounce", "mail": map[string]any{"messageId": id},
		"bounce": map[string]any{"bounceType": kind, "bounceSubType": "General",
			"bouncedRecipients": []map[string]any{{"emailAddress": address, "diagnosticCode": "550 5.1.1 user unknown"}}}}
}

// TestEmailDeliveryIsRecordedAndBouncesSuppress: every send is
// recorded; SES's signed reports update it; a hard bounce or a complaint
// suppresses the address, so the next send is refused (email.suppressed) and
// never reaches the provider; a soft bounce only records; a forged report
// changes nothing; the organisation sees what happened and may clear a
// suppression its mail caused (audited), another organisation may not; an
// invitation to a suppressed address says so; and with no provider a send
// fails instead of reporting success. Before the fix nothing was
// recorded and a send to a dead address reported success every time.
func TestEmailDeliveryIsRecordedAndBouncesSuppress(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	store := delivery.NewStore(testPool)
	ses := &fakeSES{prefix: "ses-" + uuid.NewString()}
	sender := delivery.Tracker{Next: ses, Store: store, Provider: "ses"}
	key := newSNSKey(t)
	hook := &delivery.Webhook{Store: store, TopicARNs: []string{sesTopic}, Client: &http.Client{Transport: key}}
	tenantA := createTenant(t, ctx, uniqueSlug("mail-a"))
	tenantB := createTenant(t, ctx, uniqueSlug("mail-b"))
	admin := createUserInTenant(t, ctx, tenantA)
	gone := uniqueSlug("gone") + "@example.com"
	angry := uniqueSlug("angry") + "@example.com"
	full := uniqueSlug("full") + "@example.com"

	send := func(to string) error {
		return sender.Send(ctx, notifier.Message{TenantID: tenantA.String(), TemplateKey: "invite", Channel: "email", To: to, Subject: "Hi", Body: "Hi"})
	}
	report := func(event map[string]any) int {
		rr := httptest.NewRecorder()
		r := chi.NewRouter()
		r.Route("/v1", hook.Mount)
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/webhooks/ses", bytes.NewReader(key.notification(t, event))))
		return rr.Code
	}
	status := func(providerID string) (string, string) {
		var st, reason string
		if err := testPool.QueryRow(ctx, `SELECT status, status_reason FROM platform.email_messages WHERE provider = 'ses' AND provider_message_id = $1`, providerID).Scan(&st, &reason); err != nil {
			t.Fatalf("message %s: %v", providerID, err)
		}
		return st, reason
	}
	api := func(as uuid.UUID, method, path string) (int, map[string]any) {
		r := chi.NewRouter()
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), &httpx.Principal{UserID: &admin, TenantID: &as, ActorType: "user"})))
			})
		})
		r.Route("/v1", (&email.DeliveryHandler{Store: store}).Mount)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
		out := map[string]any{}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	// A send is recorded with the provider's id.
	if err := send(gone); err != nil {
		t.Fatalf("first send: %v", err)
	}
	first := ses.prefix + "-1"
	if st, _ := status(first); st != delivery.StatusSent {
		t.Fatalf("after sending: %s, want sent", st)
	}

	// A forged report (signed by someone else) changes nothing.
	forged := key.notification(t, bounce(first, "Permanent", gone))
	other := newSNSKey(t)
	forgedHook := &delivery.Webhook{Store: store, TopicARNs: []string{sesTopic}, Client: &http.Client{Transport: other}}
	rr := httptest.NewRecorder()
	r := chi.NewRouter()
	r.Route("/v1", forgedHook.Mount)
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/webhooks/ses", bytes.NewReader(forged)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("forged report = %d, want 401", rr.Code)
	}
	if st, _ := status(first); st != delivery.StatusSent {
		t.Fatalf("after a forged report: %s, want sent", st)
	}

	// A hard bounce records and suppresses.
	if code := report(bounce(first, "Permanent", gone)); code != http.StatusNoContent {
		t.Fatalf("hard bounce report = %d", code)
	}
	if st, reason := status(first); st != delivery.StatusBounced || !strings.Contains(reason, "Permanent") {
		t.Fatalf("after a hard bounce: %s %q", st, reason)
	}
	if err := send(gone); !errors.Is(err, errs.ErrEmailSuppressed) {
		t.Fatalf("second send to a hard-bounced address = %v, want email.suppressed", err)
	}
	if ses.sent != 1 {
		t.Fatalf("the provider was asked %d times; a suppressed address never reaches it", ses.sent)
	}

	// A complaint suppresses too; a soft bounce records only; a late delivery
	// report never undoes a bounce.
	if err := send(angry); err != nil {
		t.Fatal(err)
	}
	if code := report(map[string]any{"notificationType": "Complaint", "mail": map[string]any{"messageId": ses.prefix + "-2"},
		"complaint": map[string]any{"complaintFeedbackType": "abuse", "complainedRecipients": []map[string]any{{"emailAddress": angry}}}}); code != http.StatusNoContent {
		t.Fatalf("complaint report = %d", code)
	}
	if err := send(angry); !errors.Is(err, errs.ErrEmailSuppressed) {
		t.Fatalf("send after a complaint = %v, want email.suppressed", err)
	}
	if err := send(full); err != nil {
		t.Fatal(err)
	}
	soft := ses.prefix + "-3"
	if code := report(bounce(soft, "Transient", full)); code != http.StatusNoContent {
		t.Fatalf("soft bounce report = %d", code)
	}
	if code := report(map[string]any{"eventType": "Delivery", "mail": map[string]any{"messageId": soft}}); code != http.StatusNoContent {
		t.Fatalf("delivery report = %d", code)
	}
	if st, _ := status(soft); st != delivery.StatusBounced {
		t.Fatalf("soft-bounced then delivered: %s, want bounced kept", st)
	}
	if err := send(full); err != nil {
		t.Fatalf("send after a soft bounce = %v, want sent", err)
	}

	// The organisation sees what happened and which suppression is its own.
	code, out := api(tenantA, http.MethodGet, "/v1/tenants/"+tenantA.String()+"/email/messages?to="+gone)
	items, _ := out["items"].([]any)
	sup, _ := out["suppression"].(map[string]any)
	if code != http.StatusOK || len(items) != 2 || sup == nil || sup["id"] == nil || sup["reason"] != "bounce" {
		t.Fatalf("A's view of %s = %d %v", gone, code, out)
	}
	if latest := items[0].(map[string]any); latest["status"] != delivery.StatusSuppressed {
		t.Fatalf("newest message = %v, want suppressed", latest)
	}
	supID := sup["id"].(string)
	_, outB := api(tenantB, http.MethodGet, "/v1/tenants/"+tenantB.String()+"/email/messages?to="+gone)
	if supB, _ := outB["suppression"].(map[string]any); supB == nil || supB["id"] != nil || len(outB["items"].([]any)) != 0 {
		t.Fatalf("B's view = %v, want the suppression without its id and none of A's messages", outB)
	}
	if code, _ := api(tenantB, http.MethodDelete, "/v1/tenants/"+tenantB.String()+"/email/suppressions/"+supID); code != http.StatusNotFound {
		t.Fatalf("B clearing A's suppression = %d, want 404", code)
	}
	_, list := api(tenantA, http.MethodGet, "/v1/tenants/"+tenantA.String()+"/email/suppressions")
	if n := len(list["items"].([]any)); n != 2 {
		t.Fatalf("A's suppressions = %v, want the bounce and the complaint", list)
	}

	// An invitation to the suppressed address says it wasn't sent.
	invites := invite.NewService(testPool, sender, time.Hour, "https://app.example")
	iv, _, err := invites.Create(ctx, invite.CreateInput{TenantID: tenantA, Email: gone}, &admin)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if iv.Delivery == nil || iv.Delivery.Status != "not_sent" || iv.Delivery.Code != errs.CodeEmailSuppressed {
		t.Fatalf("invite delivery = %+v, want not_sent email.suppressed", iv.Delivery)
	}

	// A clears its suppression (audited) and mail flows again.
	if code, _ := api(tenantA, http.MethodDelete, "/v1/tenants/"+tenantA.String()+"/email/suppressions/"+supID); code != http.StatusNoContent {
		t.Fatalf("A clearing its suppression = %d, want 204", code)
	}
	var audited int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'email.suppression_cleared' AND resource_id = $2`, tenantA, supID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audit rows = %d (%v), want 1", audited, err)
	}
	if err := send(gone); err != nil {
		t.Fatalf("send after clearing = %v", err)
	}
	if iv, _, err := invites.Resend(ctx, tenantA, iv.ID); err != nil || iv.Delivery == nil || iv.Delivery.Status != "sent" {
		t.Fatalf("resend after clearing = %+v, %v; want sent", iv, err)
	}

	// No provider: the send fails, and the record says why.
	nowhere := delivery.Tracker{Next: notifier.LogSender{}, Store: store, Provider: "none"}
	lost := uniqueSlug("lost") + "@example.com"
	if err := nowhere.Send(ctx, notifier.Message{TenantID: tenantA.String(), Channel: "email", To: lost, Subject: "x", Body: "x"}); !errors.Is(err, errs.ErrEmailProviderUnavailable) {
		t.Fatalf("send with no provider = %v, want email.provider_unavailable", err)
	}
	_, lostView := api(tenantA, http.MethodGet, "/v1/tenants/"+tenantA.String()+"/email/messages?to="+lost)
	if items, _ := lostView["items"].([]any); len(items) != 1 || items[0].(map[string]any)["status"] != delivery.StatusFailed {
		t.Fatalf("record of the lost message = %v, want failed", lostView)
	}
}
