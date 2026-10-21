package delivery

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testTopic   = "arn:aws:sns:ap-south-2:123456789012:qeet-id-ses-events"
	testCertURL = "https://sns.ap-south-2.amazonaws.com/SimpleNotificationService-test.pem"
)

// snsSigner signs SNS messages the way SNS does, with a certificate served at
// testCertURL by the transport below.
type snsSigner struct {
	key     *rsa.PrivateKey
	certPEM []byte
	fetched []string
}

func newSNSSigner(t *testing.T) *snsSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sns.amazonaws.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &snsSigner{key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (s *snsSigner) RoundTrip(r *http.Request) (*http.Response, error) {
	s.fetched = append(s.fetched, r.URL.String())
	body := []byte("ok")
	if r.URL.String() == testCertURL {
		body = s.certPEM
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
}

// sign fills in m's signature (version 2, SHA256withRSA) over SNS's canonical
// string, written out here independently of canonicalString.
func (s *snsSigner) sign(t *testing.T, m map[string]string) map[string]string {
	t.Helper()
	m["SignatureVersion"], m["SigningCertURL"] = "2", testCertURL
	if m["Timestamp"] == "" {
		m["Timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}
	keys := []string{"Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"}
	if m["Type"] != "Notification" {
		keys = []string{"Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"}
	}
	var b strings.Builder
	for _, k := range keys {
		if v, ok := m[k]; ok {
			b.WriteString(k + "\n" + v + "\n")
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	m["Signature"] = base64.StdEncoding.EncodeToString(sig)
	return m
}

func post(h *Webhook, m map[string]string) int {
	body, _ := json.Marshal(m)
	rr := httptest.NewRecorder()
	h.receive(rr, httptest.NewRequest(http.MethodPost, "/v1/webhooks/ses", bytes.NewReader(body)))
	return rr.Code
}

func TestWebhookVerifiesEveryMessage(t *testing.T) {
	signer := newSNSSigner(t)
	h := &Webhook{TopicARNs: []string{testTopic}, Client: &http.Client{Transport: signer}}
	ignored := `{"eventType":"Send","mail":{"messageId":"m-1"}}` // changes nothing, so no store is needed
	note := func() map[string]string {
		return map[string]string{"Type": "Notification", "MessageId": "n-1", "TopicArn": testTopic, "Message": ignored}
	}

	if code := post(h, signer.sign(t, note())); code != http.StatusNoContent {
		t.Fatalf("signed notification = %d, want 204", code)
	}

	tampered := signer.sign(t, note())
	tampered["Message"] = `{"eventType":"Send","mail":{"messageId":"m-2"}}`
	if code := post(h, tampered); code != http.StatusUnauthorized {
		t.Fatalf("message changed after signing = %d, want 401", code)
	}

	other := note()
	other["TopicArn"] = "arn:aws:sns:ap-south-2:999999999999:someone-elses-topic"
	if code := post(h, signer.sign(t, other)); code != http.StatusUnauthorized {
		t.Fatalf("validly signed, from another topic = %d, want 401", code)
	}

	v1 := signer.sign(t, note())
	v1["SignatureVersion"] = "1"
	if code := post(h, v1); code != http.StatusUnauthorized {
		t.Fatalf("SignatureVersion 1 (SHA-1) = %d, want 401", code)
	}

	stale := note()
	stale["Timestamp"] = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	if code := post(h, signer.sign(t, stale)); code != http.StatusUnauthorized {
		t.Fatalf("two-hour-old message = %d, want 401", code)
	}

	for _, certURL := range []string{
		"http://sns.ap-south-2.amazonaws.com/x.pem",
		"https://sns.ap-south-2.amazonaws.com.evil.example/x.pem",
		"https://evil.example/sns.ap-south-2.amazonaws.com/x.pem",
		"https://sns.ap-south-2.amazonaws.com/x.txt",
	} {
		m := signer.sign(t, note())
		m["SigningCertURL"] = certURL
		if code := post(h, m); code != http.StatusUnauthorized {
			t.Errorf("certificate at %s = %d, want 401", certURL, code)
		}
	}
	for _, u := range signer.fetched {
		if u != testCertURL {
			t.Errorf("fetched %s; only the SNS certificate URL may be fetched", u)
		}
	}

	if code := post(&Webhook{Client: h.Client}, signer.sign(t, note())); code != http.StatusNotFound {
		t.Fatalf("no topic configured = %d, want 404 (endpoint off)", code)
	}
}

func TestWebhookConfirmsTheSubscription(t *testing.T) {
	signer := newSNSSigner(t)
	h := &Webhook{TopicARNs: []string{testTopic}, Client: &http.Client{Transport: signer}}
	subscribe := "https://sns.ap-south-2.amazonaws.com/?Action=ConfirmSubscription&TopicArn=" + testTopic + "&Token=tok"
	m := signer.sign(t, map[string]string{
		"Type": "SubscriptionConfirmation", "MessageId": "s-1", "Token": "tok", "TopicArn": testTopic,
		"Message": "You have chosen to subscribe", "SubscribeURL": subscribe,
	})
	if code := post(h, m); code != http.StatusNoContent {
		t.Fatalf("subscription confirmation = %d, want 204", code)
	}
	if got := signer.fetched[len(signer.fetched)-1]; got != subscribe {
		t.Fatalf("visited %s, want the SubscribeURL", got)
	}

	m = signer.sign(t, map[string]string{
		"Type": "SubscriptionConfirmation", "MessageId": "s-2", "Token": "tok", "TopicArn": testTopic,
		"Message": "x", "SubscribeURL": "https://evil.example/confirm",
	})
	before := len(signer.fetched)
	if code := post(h, m); code == http.StatusNoContent {
		t.Fatalf("confirmation pointing off SNS = %d, want refused", code)
	}
	for _, u := range signer.fetched[before:] {
		if strings.Contains(u, "evil.example") {
			t.Fatalf("visited %s", u)
		}
	}
}

func TestParseSESEvent(t *testing.T) {
	for _, tc := range []struct {
		name, raw    string
		ok           bool
		status       string
		suppress     int
		reasonPrefix string
	}{
		{"hard bounce", `{"eventType":"Bounce","mail":{"messageId":"m"},"bounce":{"bounceType":"Permanent","bounceSubType":"General","bouncedRecipients":[{"emailAddress":"gone@example.com","diagnosticCode":"550 5.1.1 no such user"}]}}`, true, StatusBounced, 1, "Permanent/General: 550"},
		{"soft bounce", `{"eventType":"Bounce","mail":{"messageId":"m"},"bounce":{"bounceType":"Transient","bounceSubType":"MailboxFull","bouncedRecipients":[{"emailAddress":"full@example.com"}]}}`, true, StatusBounced, 0, "Transient/MailboxFull"},
		{"complaint", `{"notificationType":"Complaint","mail":{"messageId":"m"},"complaint":{"complaintFeedbackType":"abuse","complainedRecipients":[{"emailAddress":"angry@example.com"}]}}`, true, StatusComplained, 1, "abuse"},
		{"delivery", `{"eventType":"Delivery","mail":{"messageId":"m"},"delivery":{}}`, true, StatusDelivered, 0, ""},
		{"reject", `{"eventType":"Reject","mail":{"messageId":"m"},"reject":{"reason":"Bad content"}}`, true, StatusFailed, 0, "rejected: Bad content"},
		{"send", `{"eventType":"Send","mail":{"messageId":"m"}}`, false, "", 0, ""},
	} {
		ev, ok, err := parseSESEvent(tc.raw)
		if err != nil || ok != tc.ok || ev.Status != tc.status || len(ev.Suppress) != tc.suppress || !strings.HasPrefix(ev.Reason, tc.reasonPrefix) {
			t.Errorf("%s: %+v ok=%v err=%v", tc.name, ev, ok, err)
		}
	}
	if _, _, err := parseSESEvent(`{"eventType":"Delivery","mail":{}}`); err == nil {
		t.Error("an event with no messageId is not an SES event")
	}
}

func TestAddressHashAndHint(t *testing.T) {
	if HashAddress(" Ana@Example.COM ") != HashAddress("ana@example.com") {
		t.Error("the hash must ignore case and surrounding space")
	}
	if got := Hint("Ana.Lopez@example.com"); got != "a***@example.com" {
		t.Errorf("Hint = %q", got)
	}
	if got := Hint("not-an-address"); got != "***" {
		t.Errorf("Hint of a non-address = %q", got)
	}
}

func TestWebhookReadsNothingWithoutTopics(t *testing.T) {
	h := &Webhook{}
	rr := httptest.NewRecorder()
	h.receive(rr, httptest.NewRequest(http.MethodPost, "/v1/webhooks/ses", strings.NewReader("{")))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("= %d, want 404", rr.Code)
	}
}
