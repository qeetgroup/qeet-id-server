package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
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

	if !verifyStripeSignature(secret, header, body) {
		t.Error("valid signature rejected")
	}
	if verifyStripeSignature("wrong", header, body) {
		t.Error("wrong secret accepted")
	}
	if verifyStripeSignature(secret, fmt.Sprintf("t=%s,v1=deadbeef", ts), body) {
		t.Error("tampered signature accepted")
	}
	if verifyStripeSignature(secret, header, []byte(`{"tampered":true}`)) {
		t.Error("tampered body accepted")
	}
	if verifyStripeSignature(secret, "", body) || verifyStripeSignature("", header, body) {
		t.Error("empty secret/header accepted")
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
