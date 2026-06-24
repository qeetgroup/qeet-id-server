package notifier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TwilioSender delivers SMS via Twilio's REST API — a form-POST with HTTP basic
// auth, no SDK. It handles the "sms" channel only.
type TwilioSender struct {
	AccountSID string
	AuthToken  string
	From       string
	// BaseURL defaults to https://api.twilio.com; overridable for tests.
	BaseURL string
	Client  *http.Client
}

func (s TwilioSender) Send(ctx context.Context, m Message) error {
	if m.Channel != "sms" {
		return fmt.Errorf("twilio sender: unsupported channel %q", m.Channel)
	}
	base := s.BaseURL
	if base == "" {
		base = "https://api.twilio.com"
	}
	endpoint := base + "/2010-04-01/Accounts/" + url.PathEscape(s.AccountSID) + "/Messages.json"
	form := url.Values{"To": {m.To}, "From": {s.From}, "Body": {m.Body}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.AccountSID, s.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("twilio sms send failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
