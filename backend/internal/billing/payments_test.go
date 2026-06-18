package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
