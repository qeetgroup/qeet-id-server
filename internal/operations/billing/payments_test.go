package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyStripeSignature(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"type":"checkout.session.completed"}`)
	ts := "1700000000"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	header := fmt.Sprintf("t=%s,v1=%s", ts, sig)
	signedAt := time.Unix(1700000000, 0)

	if !verifyStripeSignature(secret, header, body, signedAt) {
		t.Error("valid signature rejected")
	}
	if verifyStripeSignature("wrong", header, body, signedAt) {
		t.Error("wrong secret accepted")
	}
	if verifyStripeSignature(secret, fmt.Sprintf("t=%s,v1=deadbeef", ts), body, signedAt) {
		t.Error("tampered signature accepted")
	}
	if verifyStripeSignature(secret, header, []byte(`{"tampered":true}`), signedAt) {
		t.Error("tampered body accepted")
	}
	if verifyStripeSignature(secret, "", body, signedAt) || verifyStripeSignature("", header, body, signedAt) {
		t.Error("empty secret/header accepted")
	}
}

// stripeSigned is the v1 signature secret makes of body at ts.
func stripeSigned(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// TestStripeSignatureAcceptsAnyV1AndRefusesStale checks that a header carrying
// several v1 signatures, as Stripe sends while a webhook secret rotates, is
// accepted when any of them is right, and that an event signed more than five
// minutes before or after now is refused however well signed.
func TestStripeSignatureAcceptsAnyV1AndRefusesStale(t *testing.T) {
	secret := "whsec_current"
	body := []byte(`{"type":"checkout.session.completed"}`)
	now := time.Unix(1800000000, 0)
	ts := "1800000000"
	good, other := stripeSigned(secret, ts, body), stripeSigned("whsec_previous", ts, body)
	for _, header := range []string{
		"t=" + ts + ",v1=" + good + ",v1=" + other,
		"t=" + ts + ",v1=" + other + ",v1=" + good,
		"t=" + ts + ",v0=" + other + ",v1=" + good,
	} {
		if !verifyStripeSignature(secret, header, body, now) {
			t.Errorf("%s: refused, want accepted (one v1 is right)", header)
		}
	}
	if verifyStripeSignature(secret, "t="+ts+",v1="+other+",v1=deadbeef", body, now) {
		t.Error("no right v1: accepted")
	}
	for name, at := range map[string]time.Time{
		"signed six minutes ago":      now.Add(6 * time.Minute),
		"signed six minutes from now": now.Add(-6 * time.Minute),
		"signed a day ago":            now.Add(24 * time.Hour),
	} {
		if verifyStripeSignature(secret, "t="+ts+",v1="+good, body, at) {
			t.Errorf("an event %s: accepted, want refused", name)
		}
	}
	if !verifyStripeSignature(secret, "t="+ts+",v1="+good, body, now.Add(4*time.Minute)) {
		t.Error("an event signed four minutes ago: refused, want accepted")
	}
	if verifyStripeSignature(secret, "t=soon,v1="+stripeSigned(secret, "soon", body), body, now) {
		t.Error("a timestamp that isn't a number: accepted")
	}
}

func TestVerifyRazorpaySignature(t *testing.T) {
	secret := "rzp_webhook_secret"
	body := []byte(`{"event":"payment_link.paid"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	if !verifyRazorpaySignature(secret, sig, body) {
		t.Error("valid signature rejected")
	}
	if verifyRazorpaySignature("wrong", sig, body) {
		t.Error("wrong secret accepted")
	}
	if verifyRazorpaySignature(secret, "deadbeef", body) {
		t.Error("tampered signature accepted")
	}
	if verifyRazorpaySignature(secret, sig, []byte(`{"tampered":true}`)) {
		t.Error("tampered body accepted")
	}
}

func TestForCurrencyRouting(t *testing.T) {
	both := NewPayments("sk_test", "wh", "rzp_id", "rzp_secret", "rzp_wh")
	if p := both.forCurrency("INR"); p == nil || p.Name() != "razorpay" {
		t.Errorf("INR should route to razorpay, got %v", p)
	}
	if p := both.forCurrency("USD"); p == nil || p.Name() != "stripe" {
		t.Errorf("USD should route to stripe, got %v", p)
	}

	stripeOnly := NewPayments("sk_test", "wh", "", "", "")
	if p := stripeOnly.forCurrency("INR"); p != nil {
		t.Error("INR with no razorpay should be nil (don't silently use stripe for INR)")
	}
	if p := stripeOnly.forCurrency("EUR"); p == nil || p.Name() != "stripe" {
		t.Error("EUR should route to stripe when configured")
	}

	none := NewPayments("", "", "", "", "")
	if none.Enabled() {
		t.Error("no keys should mean disabled")
	}
	if none.forCurrency("USD") != nil {
		t.Error("no provider should route to nil")
	}
}

func TestForCountryRouting(t *testing.T) {
	both := NewPayments("sk_test", "wh", "rzp_id", "rzp_secret", "rzp_wh").
		WithRouting("stripe", map[string]string{"IN": "razorpay"})

	if p := both.forCountry("IN"); p == nil || p.Name() != "razorpay" {
		t.Errorf("IN should route to razorpay, got %v", p)
	}
	if p := both.forCountry("in"); p == nil || p.Name() != "razorpay" {
		t.Errorf("country match should be case-insensitive, got %v", p)
	}
	if p := both.forCountry("US"); p == nil || p.Name() != "stripe" {
		t.Errorf("unlisted country should use the default (stripe), got %v", p)
	}
	if p := both.forCountry(""); p == nil || p.Name() != "stripe" {
		t.Errorf("empty country should use the default (stripe), got %v", p)
	}

	// A route/default pointing at an unconfigured provider resolves to nil rather
	// than silently falling through to another provider.
	razorpayOnly := NewPayments("", "", "rzp_id", "rzp_secret", "rzp_wh").
		WithRouting("stripe", nil)
	if p := razorpayOnly.forCountry("US"); p != nil {
		t.Errorf("default stripe not configured should be nil, got %v", p)
	}

	noDefault := NewPayments("sk_test", "wh", "", "", "").WithRouting("", nil)
	if p := noDefault.forCountry("US"); p != nil {
		t.Errorf("no default provider should be nil, got %v", p)
	}
}

func TestParseCountryRoutes(t *testing.T) {
	routes := ParseCountryRoutes(" in : razorpay , US:stripe , garbage , :x , Y: ")
	if len(routes) != 2 {
		t.Fatalf("expected 2 valid routes, got %d: %v", len(routes), routes)
	}
	if routes["IN"] != "razorpay" {
		t.Errorf("IN should normalize to razorpay, got %q", routes["IN"])
	}
	if routes["US"] != "stripe" {
		t.Errorf("US should map to stripe, got %q", routes["US"])
	}
	if got := ParseCountryRoutes(""); len(got) != 0 {
		t.Errorf("empty string should parse to empty map, got %v", got)
	}
}

func TestSandboxOverridesRouting(t *testing.T) {
	p := NewPayments("sk_test", "wh", "rzp_id", "rzp_secret", "rzp_wh").
		WithRouting("stripe", map[string]string{"IN": "razorpay"}).
		WithSandbox("http://localhost:4001", "secret")

	if !p.SandboxEnabled() {
		t.Fatal("sandbox should be enabled")
	}
	// Sandbox serves every checkout regardless of country/currency.
	if pr := p.forCountry("IN"); pr == nil || pr.Name() != "sandbox" {
		t.Errorf("sandbox should override country routing, got %v", pr)
	}
	if pr := p.forCurrency("INR"); pr == nil || pr.Name() != "sandbox" {
		t.Errorf("sandbox should override currency routing, got %v", pr)
	}

	// CreateCheckout points at the local mock page and round-trips our ref.
	got, ref, err := p.forCurrency("USD").CreateCheckout(context.Background(), CheckoutInput{
		Ref: "abc", PlanName: "Pro", Currency: "USD", AmountMinor: 9900,
		SuccessURL: "http://localhost:3002/ok", CancelURL: "http://localhost:3002/no",
	})
	if err != nil {
		t.Fatalf("sandbox CreateCheckout: %v", err)
	}
	if !strings.Contains(got, "/v1/billing/sandbox/checkout") || !strings.Contains(got, "ref=abc") {
		t.Errorf("unexpected sandbox url: %s", got)
	}
	if ref == "" {
		t.Error("expected a provider ref")
	}
}

// TestProvidersSayWhatPaid checks that a payment's method is read from
// Razorpay's paid webhook, and looked up from the payment intent Stripe's
// completed session names.
func TestProvidersSayWhatPaid(t *testing.T) {
	ctx := context.Background()
	rzp := &razorpayProvider{}
	for name, c := range map[string]struct {
		body string
		want PaymentMethod
	}{
		"card":       {`{"payload":{"payment":{"entity":{"method":"card","card":{"network":"RuPay","last4":"1111"}}}}}`, PaymentMethod{Type: "card", Brand: "RuPay", Last4: "1111"}},
		"netbanking": {`{"payload":{"payment":{"entity":{"method":"netbanking","bank":"HDFC"}}}}`, PaymentMethod{Type: "netbanking", Brand: "HDFC"}},
		"upi":        {`{"payload":{"payment":{"entity":{"method":"upi","vpa":"someone@bank"}}}}`, PaymentMethod{Type: "upi"}},
	} {
		got, err := rzp.PaymentMethod(ctx, []byte(c.body))
		if err != nil || got == nil || *got != c.want {
			t.Errorf("razorpay %s: %+v, %v; want %+v", name, got, err, c.want)
		}
	}
	if got, err := rzp.PaymentMethod(ctx, []byte(`{"payload":{}}`)); err != nil || got != nil {
		t.Errorf("razorpay with no payment: %+v, %v", got, err)
	}

	var asked string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path + "?" + r.URL.RawQuery
		if u, _, ok := r.BasicAuth(); !ok || u != "sk_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"id":"pi_1","payment_method":{"type":"card","card":{"brand":"mastercard","last4":"4444","exp_month":3,"exp_year":2029}}}`))
	}))
	defer api.Close()
	stripe := &stripeProvider{secretKey: "sk_test", client: api.Client(), apiBase: api.URL}
	got, err := stripe.PaymentMethod(ctx, []byte(`{"data":{"object":{"payment_intent":"pi_1"}}}`))
	want := PaymentMethod{Type: "card", Brand: "mastercard", Last4: "4444", ExpMonth: 3, ExpYear: 2029}
	if err != nil || got == nil || *got != want || asked != "/v1/payment_intents/pi_1?expand[]=payment_method" {
		t.Errorf("stripe: %+v, %v after asking %q; want %+v", got, err, asked, want)
	}
	if got, err := stripe.PaymentMethod(ctx, []byte(`{"data":{"object":{}}}`)); err != nil || got != nil {
		t.Errorf("stripe session with no payment intent: %+v, %v", got, err)
	}
}
