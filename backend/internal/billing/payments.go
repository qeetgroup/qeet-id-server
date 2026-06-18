package billing

// Card-payment providers (Stripe, Razorpay) for paid plan changes, implemented
// against each provider's REST API (no SDK dependency). The model is one-time
// payment per billing period: a hosted checkout returns a redirect URL, and the
// provider's success webhook completes the checkout (activating the plan). Each
// provider is optional — disabled until its keys are configured — so dev/CI and
// invoice-only deployments are unaffected.
//
// Webhook signatures are verified with the provider's shared secret. Replay is
// harmless because CompleteCheckout is idempotent (a checkout activates once).

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CheckoutInput is what a provider needs to open a hosted payment for one
// period of a plan. Ref is our billing_checkouts row id, round-tripped through
// the provider so the webhook can correlate the payment back to the checkout.
type CheckoutInput struct {
	Ref         string
	PlanName    string
	Currency    string
	AmountMinor int64
	SuccessURL  string
	CancelURL   string
}

// PaymentProvider is one card processor.
type PaymentProvider interface {
	Name() string
	// CreateCheckout opens a hosted payment and returns the URL to redirect the
	// payer to, plus the provider's own reference (stored for audit).
	CreateCheckout(ctx context.Context, in CheckoutInput) (redirectURL, providerRef string, err error)
	// VerifyAndParse authenticates a webhook against its signature and returns
	// our checkout ref and whether it represents a successful payment. A
	// non-payment event returns ("", false, nil).
	VerifyAndParse(body []byte, signature string) (ref string, paid bool, err error)
	// SignatureHeader is the HTTP header carrying the webhook signature.
	SignatureHeader() string
}

// Payments routes checkouts to a configured provider by currency and looks
// providers up by name for webhook dispatch.
type Payments struct {
	stripe   *stripeProvider
	razorpay *razorpayProvider
}

// NewPayments builds the set of configured providers; empty keys leave a
// provider disabled (nil).
func NewPayments(stripeKey, stripeWebhookSecret, razorpayKeyID, razorpayKeySecret, razorpayWebhookSecret string) *Payments {
	client := &http.Client{Timeout: 15 * time.Second}
	p := &Payments{}
	if stripeKey != "" {
		p.stripe = &stripeProvider{secretKey: stripeKey, webhookSecret: stripeWebhookSecret, client: client}
	}
	if razorpayKeyID != "" && razorpayKeySecret != "" {
		p.razorpay = &razorpayProvider{keyID: razorpayKeyID, keySecret: razorpayKeySecret, webhookSecret: razorpayWebhookSecret, client: client}
	}
	return p
}

// Enabled reports whether any provider is configured.
func (p *Payments) Enabled() bool { return p != nil && (p.stripe != nil || p.razorpay != nil) }

// forCurrency picks the provider for a currency: INR → Razorpay, everything
// else → Stripe, falling back to whichever single provider is configured.
// Returns nil when none can serve the currency.
func (p *Payments) forCurrency(currency string) PaymentProvider {
	if p == nil {
		return nil
	}
	if strings.EqualFold(currency, "INR") {
		if p.razorpay != nil {
			return p.razorpay
		}
		return nil // INR is Razorpay-only; don't silently charge via Stripe
	}
	if p.stripe != nil {
		return p.stripe
	}
	return nil
}

// byName resolves a provider for webhook dispatch.
func (p *Payments) byName(name string) PaymentProvider {
	switch name {
	case "stripe":
		if p.stripe != nil {
			return p.stripe
		}
	case "razorpay":
		if p.razorpay != nil {
			return p.razorpay
		}
	}
	return nil
}

// --- Stripe ---

type stripeProvider struct {
	secretKey     string
	webhookSecret string
	client        *http.Client
}

func (s *stripeProvider) Name() string            { return "stripe" }
func (s *stripeProvider) SignatureHeader() string { return "Stripe-Signature" }

func (s *stripeProvider) CreateCheckout(ctx context.Context, in CheckoutInput) (string, string, error) {
	form := url.Values{}
	form.Set("mode", "payment")
	form.Set("success_url", in.SuccessURL)
	form.Set("cancel_url", in.CancelURL)
	form.Set("client_reference_id", in.Ref)
	form.Set("line_items[0][quantity]", "1")
	form.Set("line_items[0][price_data][currency]", strings.ToLower(in.Currency))
	form.Set("line_items[0][price_data][unit_amount]", strconv.FormatInt(in.AmountMinor, 10))
	form.Set("line_items[0][price_data][product_data][name]", in.PlanName)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.stripe.com/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.SetBasicAuth(s.secretKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("stripe checkout failed: %s", strings.TrimSpace(string(rb)))
	}
	var out struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", "", err
	}
	if out.URL == "" {
		return "", "", errors.New("stripe returned no checkout url")
	}
	return out.URL, out.ID, nil
}

func (s *stripeProvider) VerifyAndParse(body []byte, signature string) (string, bool, error) {
	if !verifyStripeSignature(s.webhookSecret, signature, body) {
		return "", false, errors.New("invalid stripe signature")
	}
	var evt struct {
		Type string `json:"type"`
		Data struct {
			Object struct {
				ClientReferenceID string `json:"client_reference_id"`
				PaymentStatus     string `json:"payment_status"`
			} `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &evt); err != nil {
		return "", false, err
	}
	if evt.Type == "checkout.session.completed" && evt.Data.Object.PaymentStatus == "paid" {
		return evt.Data.Object.ClientReferenceID, true, nil
	}
	return "", false, nil
}

// verifyStripeSignature checks a `t=...,v1=...` Stripe-Signature header: the v1
// HMAC-SHA256 of "<t>.<body>" keyed by the webhook secret. Constant-time.
func verifyStripeSignature(secret, header string, body []byte) bool {
	if secret == "" || header == "" {
		return false
	}
	var ts, v1 string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			v1 = kv[1]
		}
	}
	if ts == "" || v1 == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(v1))
}

// --- Razorpay ---

type razorpayProvider struct {
	keyID         string
	keySecret     string
	webhookSecret string
	client        *http.Client
}

func (r *razorpayProvider) Name() string            { return "razorpay" }
func (r *razorpayProvider) SignatureHeader() string { return "X-Razorpay-Signature" }

func (r *razorpayProvider) CreateCheckout(ctx context.Context, in CheckoutInput) (string, string, error) {
	payload := map[string]any{
		"amount":          in.AmountMinor,
		"currency":        strings.ToUpper(in.Currency),
		"description":     in.PlanName,
		"callback_url":    in.SuccessURL,
		"callback_method": "get",
		"notes":           map[string]string{"checkout_ref": in.Ref},
	}
	bb, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.razorpay.com/v1/payment_links", bytes.NewReader(bb))
	if err != nil {
		return "", "", err
	}
	req.SetBasicAuth(r.keyID, r.keySecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("razorpay payment link failed: %s", strings.TrimSpace(string(rb)))
	}
	var out struct {
		ID       string `json:"id"`
		ShortURL string `json:"short_url"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", "", err
	}
	if out.ShortURL == "" {
		return "", "", errors.New("razorpay returned no payment link url")
	}
	return out.ShortURL, out.ID, nil
}

func (r *razorpayProvider) VerifyAndParse(body []byte, signature string) (string, bool, error) {
	if !verifyRazorpaySignature(r.webhookSecret, signature, body) {
		return "", false, errors.New("invalid razorpay signature")
	}
	var evt struct {
		Event   string `json:"event"`
		Payload struct {
			PaymentLink struct {
				Entity struct {
					Notes map[string]string `json:"notes"`
				} `json:"entity"`
			} `json:"payment_link"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &evt); err != nil {
		return "", false, err
	}
	if evt.Event == "payment_link.paid" {
		return evt.Payload.PaymentLink.Entity.Notes["checkout_ref"], true, nil
	}
	return "", false, nil
}

// verifyRazorpaySignature checks the X-Razorpay-Signature header: the hex
// HMAC-SHA256 of the raw body keyed by the webhook secret. Constant-time. Also
// accepts a base64-encoded signature for robustness.
func verifyRazorpaySignature(secret, signature string, body []byte) bool {
	if secret == "" || signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sum := mac.Sum(nil)
	expectedHex := hex.EncodeToString(sum)
	if hmac.Equal([]byte(expectedHex), []byte(signature)) {
		return true
	}
	expectedB64 := base64.StdEncoding.EncodeToString(sum)
	return hmac.Equal([]byte(expectedB64), []byte(signature))
}
