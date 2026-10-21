package delivery

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SNS SignatureVersion 1 is SHA1withRSA; version 2 is preferred and supported
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Webhook receives Amazon SES events through Amazon SNS
// (POST /v1/webhooks/ses): it verifies each SNS message's signature, confirms
// the subscription, and applies bounces, complaints and deliveries to the
// records.
//
// Anyone can create an SNS topic, and SNS signs its messages too, so a valid
// signature alone proves nothing: a message is accepted only from a topic in
// TopicARNs. With none configured the endpoint is off (404).
type Webhook struct {
	Store     *Store
	TopicARNs []string
	// Client fetches signing certificates and confirms subscriptions; nil uses
	// a client with a 5 s timeout.
	Client *http.Client
	// Now is the clock (tests); nil uses time.Now.
	Now func() time.Time

	certMu sync.Mutex
	certs  map[string]*x509.Certificate
}

// snsHost is the only host SNS signs from and confirms subscriptions on.
var snsHost = regexp.MustCompile(`^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`)

// maxMessageAge bounds replay of a captured, validly signed message.
const maxMessageAge = time.Hour

type snsMessage struct {
	Type             string `json:"Type"`
	MessageID        string `json:"MessageId"`
	Token            string `json:"Token"`
	TopicArn         string `json:"TopicArn"`
	Subject          string `json:"Subject"`
	Message          string `json:"Message"`
	Timestamp        string `json:"Timestamp"`
	SignatureVersion string `json:"SignatureVersion"`
	Signature        string `json:"Signature"`
	SigningCertURL   string `json:"SigningCertURL"`
	SubscribeURL     string `json:"SubscribeURL"`
}

// Mount registers POST /webhooks/ses (under /v1, public: SNS signs, it
// holds no session).
func (h *Webhook) Mount(r chi.Router) {
	r.Post("/webhooks/ses", h.receive)
}

func (h *Webhook) receive(w http.ResponseWriter, r *http.Request) {
	if len(h.TopicARNs) == 0 {
		httpx.WriteError(w, r, errs.ErrEmailWebhookDisabled)
		return
	}
	var m snsMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 300<<10)).Decode(&m); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("not an SNS message"))
		return
	}
	if !slices.Contains(h.TopicARNs, m.TopicArn) {
		httpx.WriteError(w, r, errs.ErrEmailWebhookSignature.WithDetail("unexpected topic"))
		return
	}
	if err := h.verify(r.Context(), m); err != nil {
		slog.Warn("ses webhook: message refused", "err", err, "topic", m.TopicArn, "type", m.Type)
		httpx.WriteError(w, r, errs.ErrEmailWebhookSignature)
		return
	}

	switch m.Type {
	case "SubscriptionConfirmation":
		if err := h.confirm(r.Context(), m.SubscribeURL); err != nil {
			slog.Error("ses webhook: subscription confirmation failed", "err", err, "topic", m.TopicArn)
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("subscription not confirmed"))
			return
		}
		slog.Info("ses webhook: subscription confirmed", "topic", m.TopicArn)
	case "Notification":
		ev, ok, err := parseSESEvent(m.Message)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("not an SES event"))
			return
		}
		if ok {
			if err := h.Store.Apply(r.Context(), ev); err != nil {
				httpx.WriteError(w, r, err) // SNS retries a failure
				return
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// verify checks m's signature against its signing certificate, which must be
// served by SNS itself, and that it isn't stale.
func (h *Webhook) verify(ctx context.Context, m snsMessage) error {
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	ts, err := time.Parse(time.RFC3339, m.Timestamp)
	if err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	if age := now().Sub(ts); age > maxMessageAge || age < -5*time.Minute {
		return fmt.Errorf("timestamp %s out of range", m.Timestamp)
	}
	var hash crypto.Hash
	switch m.SignatureVersion {
	case "1":
		hash = crypto.SHA1
	case "2":
		hash = crypto.SHA256
	default:
		return fmt.Errorf("signature version %q", m.SignatureVersion)
	}
	canonical, err := canonicalString(m)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	cert, err := h.cert(ctx, m.SigningCertURL)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("signing certificate has no RSA key")
	}
	var digest []byte
	if hash == crypto.SHA1 {
		sum := sha1.Sum([]byte(canonical)) //nolint:gosec // see the import
		digest = sum[:]
	} else {
		sum := sha256.Sum256([]byte(canonical))
		digest = sum[:]
	}
	return rsa.VerifyPKCS1v15(pub, hash, digest, sig)
}

// canonicalString is what SNS signs: the message's fields, by type, each as
// "Name\nvalue\n" in byte order of the names.
func canonicalString(m snsMessage) (string, error) {
	var fields [][2]string
	switch m.Type {
	case "Notification":
		fields = [][2]string{{"Message", m.Message}, {"MessageId", m.MessageID}}
		if m.Subject != "" {
			fields = append(fields, [2]string{"Subject", m.Subject})
		}
		fields = append(fields, [2]string{"Timestamp", m.Timestamp}, [2]string{"TopicArn", m.TopicArn}, [2]string{"Type", m.Type})
	case "SubscriptionConfirmation", "UnsubscribeConfirmation":
		fields = [][2]string{
			{"Message", m.Message}, {"MessageId", m.MessageID}, {"SubscribeURL", m.SubscribeURL},
			{"Timestamp", m.Timestamp}, {"Token", m.Token}, {"TopicArn", m.TopicArn}, {"Type", m.Type},
		}
	default:
		return "", fmt.Errorf("message type %q", m.Type)
	}
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(f[0] + "\n" + f[1] + "\n")
	}
	return b.String(), nil
}

// snsURL accepts only an https URL on an SNS host.
func snsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || !snsHost.MatchString(u.Hostname()) || u.Port() != "" || u.User != nil {
		return nil, fmt.Errorf("%q is not an SNS URL", raw)
	}
	return u, nil
}

func (h *Webhook) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// cert fetches (and caches) the signing certificate at raw.
func (h *Webhook) cert(ctx context.Context, raw string) (*x509.Certificate, error) {
	u, err := snsURL(raw)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(u.Path, ".pem") {
		return nil, fmt.Errorf("%q is not a certificate", raw)
	}
	h.certMu.Lock()
	cached := h.certs[raw]
	h.certMu.Unlock()
	if cached != nil && time.Now().Before(cached.NotAfter) {
		return cached, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signing certificate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch signing certificate: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("signing certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("signing certificate is not valid now")
	}
	h.certMu.Lock()
	if h.certs == nil {
		h.certs = map[string]*x509.Certificate{}
	}
	h.certs[raw] = cert
	h.certMu.Unlock()
	return cert, nil
}

// confirm completes an SNS subscription by visiting its SubscribeURL.
func (h *Webhook) confirm(ctx context.Context, raw string) error {
	u, err := snsURL(raw)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("confirm subscription: %s", resp.Status)
	}
	return nil
}

// sesEvent is the part of an SES event (configuration-set event publishing,
// eventType) or notification (identity notifications, notificationType) read.
type sesEvent struct {
	EventType        string `json:"eventType"`
	NotificationType string `json:"notificationType"`
	Mail             struct {
		MessageID string `json:"messageId"`
	} `json:"mail"`
	Bounce *struct {
		BounceType        string `json:"bounceType"`
		BounceSubType     string `json:"bounceSubType"`
		BouncedRecipients []struct {
			EmailAddress   string `json:"emailAddress"`
			DiagnosticCode string `json:"diagnosticCode"`
		} `json:"bouncedRecipients"`
	} `json:"bounce"`
	Complaint *struct {
		ComplaintFeedbackType string `json:"complaintFeedbackType"`
		ComplainedRecipients  []struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"complainedRecipients"`
	} `json:"complaint"`
	Reject *struct {
		Reason string `json:"reason"`
	} `json:"reject"`
}

// parseSESEvent maps an SES event to an Event; ok is false for kinds that
// change nothing here (Send, DeliveryDelay, Open …).
func parseSESEvent(raw string) (Event, bool, error) {
	var e sesEvent
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return Event{}, false, err
	}
	kind := e.EventType
	if kind == "" {
		kind = e.NotificationType
	}
	ev := Event{Provider: "ses", ProviderMessageID: e.Mail.MessageID}
	if ev.ProviderMessageID == "" {
		return Event{}, false, errors.New("no messageId")
	}
	switch kind {
	case "Delivery":
		ev.Status = StatusDelivered
	case "Bounce":
		if e.Bounce == nil {
			return Event{}, false, errors.New("bounce without details")
		}
		ev.Status = StatusBounced
		ev.Reason = strings.TrimSuffix(e.Bounce.BounceType+"/"+e.Bounce.BounceSubType, "/")
		if len(e.Bounce.BouncedRecipients) > 0 && e.Bounce.BouncedRecipients[0].DiagnosticCode != "" {
			ev.Reason += ": " + truncate(e.Bounce.BouncedRecipients[0].DiagnosticCode, 200)
		}
		// Only a hard bounce suppresses: the address doesn't exist. A soft one
		// (mailbox full, a transient failure) is recorded only.
		if e.Bounce.BounceType == "Permanent" {
			for _, r := range e.Bounce.BouncedRecipients {
				ev.Suppress = append(ev.Suppress, r.EmailAddress)
			}
		}
	case "Complaint":
		ev.Status = StatusComplained
		if e.Complaint != nil {
			ev.Reason = e.Complaint.ComplaintFeedbackType
			for _, r := range e.Complaint.ComplainedRecipients {
				ev.Suppress = append(ev.Suppress, r.EmailAddress)
			}
		}
	case "Reject":
		ev.Status = StatusFailed
		if e.Reject != nil {
			ev.Reason = "rejected: " + e.Reject.Reason
		}
	default:
		return Event{}, false, nil
	}
	return ev, true, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
