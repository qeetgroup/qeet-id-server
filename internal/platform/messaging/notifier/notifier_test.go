package notifier

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

type recordSender struct{ last *Message }

func (r *recordSender) Send(_ context.Context, m Message) error {
	r.last = &m
	return nil
}

func TestRouter_DispatchesByChannel(t *testing.T) {
	email, sms := &recordSender{}, &recordSender{}
	r := Router{Email: email, SMS: sms, Default: &recordSender{}}
	_ = r.Send(context.Background(), Message{Channel: "sms", To: "+15550001111"})
	_ = r.Send(context.Background(), Message{Channel: "email", To: "a@b.test"})
	_ = r.Send(context.Background(), Message{Channel: "", To: "c@d.test"}) // empty ⇒ email
	if sms.last == nil || sms.last.To != "+15550001111" {
		t.Errorf("sms not routed: %+v", sms.last)
	}
	if email.last == nil || email.last.To != "c@d.test" {
		t.Errorf("email/empty-channel not routed: %+v", email.last)
	}
}

func TestRouter_FallsBackToDefault(t *testing.T) {
	def := &recordSender{}
	r := Router{Default: def} // no email/sms providers
	_ = r.Send(context.Background(), Message{Channel: "email", To: "x@y.test"})
	if def.last == nil || def.last.To != "x@y.test" {
		t.Error("default should receive messages for unconfigured channels")
	}
}

func TestNew_WiresConfiguredProviders(t *testing.T) {
	emailOnly := New(Config{SMTPHost: "smtp.example", SMTPFrom: "no-reply@example"}).(Router)
	if emailOnly.Email == nil {
		t.Error("SMTP config should wire the email sender")
	}
	if emailOnly.SMS != nil {
		t.Error("no Twilio config should leave SMS unset")
	}

	both := New(Config{
		SMTPHost: "smtp.example", SMTPFrom: "no-reply@example",
		TwilioAccountSID: "AC", TwilioAuthToken: "tok", TwilioFrom: "+1",
	}).(Router)
	if both.SMS == nil {
		t.Error("Twilio config should wire the SMS sender")
	}

	none := New(Config{}).(Router)
	if none.Email != nil || none.SMS != nil {
		t.Error("empty config should leave both channels unconfigured")
	}
	if none.Default == nil {
		t.Error("Default must always be set (LogSender fallback)")
	}
}

func TestBuildMIME(t *testing.T) {
	msg := string(buildMIME("Qeet <no-reply@q.test>", "u@x.test", "Hi there", "Body line", ""))
	for _, want := range []string{"From: Qeet <no-reply@q.test>", "To: u@x.test", "Subject: Hi there", "text/plain", "Body line"} {
		if !strings.Contains(msg, want) {
			t.Errorf("MIME missing %q in:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "multipart") {
		t.Error("text-only mail should not be multipart")
	}
}

func TestBuildMIME_HTMLMultipart(t *testing.T) {
	msg := string(buildMIME("Qeet <no-reply@q.test>", "u@x.test", "Hi", "plain fallback", "<p>rich</p>"))
	for _, want := range []string{
		"multipart/alternative", "text/plain", "plain fallback", "text/html", "<p>rich</p>",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("HTML MIME missing %q in:\n%s", want, msg)
		}
	}
	// Text part must come before the HTML part so clients prefer HTML.
	if strings.Index(msg, "text/plain") > strings.Index(msg, "text/html") {
		t.Error("text/plain part must precede text/html")
	}
}

func TestFromAddress(t *testing.T) {
	if got := fromAddress("Qeet ID <no-reply@q.test>"); got != "no-reply@q.test" {
		t.Errorf("display-name form = %q", got)
	}
	if got := fromAddress("bare@q.test"); got != "bare@q.test" {
		t.Errorf("bare form = %q", got)
	}
}

func TestTenantEmailHeaders(t *testing.T) {
	from := messageFrom("Qeet ID <platform@example.test>", "Example Auth")
	if fromAddress(from) != "platform@example.test" || !strings.Contains(from, "Example Auth") {
		t.Fatalf("custom name changed provider-approved address: %s", from)
	}
	message := string(buildMIME(from, "user@example.test", "Notice", "Body", "", "support@example.test"))
	if !strings.Contains(message, "Reply-To: support@example.test\r\n") {
		t.Fatal("missing reply-to header")
	}
	message = string(buildMIME(from, "user@example.test", "Notice", "Body", "", "support@example.test\r\nBcc: other@example.test"))
	if strings.Contains(message, "Reply-To:") || strings.Contains(message, "Bcc:") {
		t.Fatal("unsafe reply-to header was emitted")
	}
}

type recordedSES struct{ input *sesv2.SendEmailInput }

func (client *recordedSES) SendEmail(_ context.Context, input *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	client.input = input
	return &sesv2.SendEmailOutput{}, nil
}

func TestTenantSESHeaders(t *testing.T) {
	client := &recordedSES{}
	sender := &SESv2Sender{client: client, from: "Qeet ID <platform@example.test>"}
	if err := sender.Send(context.Background(), Message{To: "user@example.test", Channel: "email", FromName: "Organization", ReplyTo: "reply@example.test", Subject: "Notice", Body: "Body"}); err != nil {
		t.Fatal(err)
	}
	if fromAddress(*client.input.FromEmailAddress) != "platform@example.test" || !strings.Contains(*client.input.FromEmailAddress, "Organization") {
		t.Fatal("provider sender identity changed")
	}
	if len(client.input.ReplyToAddresses) != 1 || client.input.ReplyToAddresses[0] != "reply@example.test" {
		t.Fatal("reply-to not delivered")
	}
}

func TestTwilioSender_SendsForm(t *testing.T) {
	var gotAuthUser, gotPath, gotForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		u, p, _ := r.BasicAuth()
		gotAuthUser = u + ":" + p
		_ = r.ParseForm()
		gotForm = r.Form.Get("To") + "|" + r.Form.Get("From") + "|" + r.Form.Get("Body")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM1"}`))
	}))
	defer srv.Close()

	s := TwilioSender{AccountSID: "AC123", AuthToken: "tok", From: "+15550001111", BaseURL: srv.URL, Client: srv.Client()}
	if err := s.Send(context.Background(), Message{Channel: "sms", To: "+15557654321", Body: "code 123"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotAuthUser != "AC123:tok" {
		t.Errorf("basic auth = %q", gotAuthUser)
	}
	if gotPath != "/2010-04-01/Accounts/AC123/Messages.json" {
		t.Errorf("path = %q", gotPath)
	}
	if gotForm != "+15557654321|+15550001111|code 123" {
		t.Errorf("form = %q", gotForm)
	}
	// Wrong channel is rejected.
	if err := s.Send(context.Background(), Message{Channel: "email", To: "x@y"}); err == nil {
		t.Error("twilio must reject a non-sms channel")
	}
}

func TestTwilioSender_ErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"invalid To"}`))
	}))
	defer srv.Close()
	s := TwilioSender{AccountSID: "AC", AuthToken: "t", From: "+1", BaseURL: srv.URL, Client: srv.Client()}
	if err := s.Send(context.Background(), Message{Channel: "sms", To: "+1", Body: "x"}); err == nil {
		t.Error("expected an error on HTTP 400")
	}
}

// TestLogSenderDoesNotLeakCredentialsOutsideDev is the regression test for the
// credential-logging leak.
//
// LogSender is the fallback for any channel with no provider configured. It
// used to log the message body unconditionally, and every credential-bearing
// message the product sends flows through this struct: MFA sign-in OTPs, email
// and SMS verification codes, password-reset links, magic links and invitation
// tokens. slog's redacting handler does not save us — it matches attribute
// keys, and "body" is just a string.
//
// This is not a dev-only path. A deployment with no Twilio credentials routes
// every SMS OTP here, and an SES init failure downgrades email to it at boot.
func TestLogSenderDoesNotLeakCredentialsOutsideDev(t *testing.T) {
	const secret = "Reset your password: https://app.example/forgot-password?token=SUPERSECRET123"

	capture := func(s LogSender) string {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
		t.Cleanup(func() { slog.SetDefault(prev) })
		err := s.Send(context.Background(), Message{
			Channel: "sms", To: "+15550000000", Subject: "Your code", Body: secret,
		})
		// The message reached nobody outside development, so it is never a
		// success there (QTID-115); in development the log is the delivery.
		if s.Reveal && err != nil {
			t.Fatalf("Send in development: %v", err)
		}
		if !s.Reveal && !errors.Is(err, errs.ErrEmailProviderUnavailable) {
			t.Fatalf("Send outside development = %v, want email.provider_unavailable", err)
		}
		return buf.String()
	}

	// Production shape: zero value, and whatever Router falls back to.
	if out := capture(LogSender{}); strings.Contains(out, "SUPERSECRET123") {
		t.Errorf("zero-value LogSender leaked the message body:\n%s", out)
	}
	if out := capture(LogSender{Reveal: false}); strings.Contains(out, "SUPERSECRET123") {
		t.Errorf("LogSender{Reveal:false} leaked the message body:\n%s", out)
	}

	// Development keeps the body — reading the OTP from the console is the
	// entire purpose of the fallback, so this must not regress either.
	if out := capture(LogSender{Reveal: true}); !strings.Contains(out, "SUPERSECRET123") {
		t.Errorf("LogSender{Reveal:true} dropped the body; dev DX regressed:\n%s", out)
	}
}

// TestNewRouterRevealsOnlyInDev pins the wiring: notifier.New must not hand the
// fallback a revealing LogSender unless Config.Dev is set.
func TestNewRouterRevealsOnlyInDev(t *testing.T) {
	for _, dev := range []bool{false, true} {
		r, ok := New(Config{Dev: dev}).(Router)
		if !ok {
			t.Fatalf("New did not return a Router")
		}
		ls, ok := r.Default.(LogSender)
		if !ok {
			t.Fatalf("Router.Default is %T, want LogSender", r.Default)
		}
		if ls.Reveal != dev {
			t.Errorf("Config{Dev:%v} produced LogSender{Reveal:%v}", dev, ls.Reveal)
		}
	}
}

// TestRouterConfigured: a channel can deliver with a real provider, and in
// development through the log that prints the message; outside development the
// log fallback reaches nobody.
func TestRouterConfigured(t *testing.T) {
	provider := LogSender{}
	cases := []struct {
		name    string
		r       Router
		channel string
		want    bool
	}{
		{"email provider", Router{Email: provider, Default: LogSender{}}, "email", true},
		{"no email provider in production", Router{Default: LogSender{}}, "email", false},
		{"no SMS provider in production", Router{Email: provider, Default: LogSender{}}, "sms", false},
		{"SMS provider", Router{SMS: provider, Default: LogSender{}}, "sms", true},
		{"development log", Router{Default: LogSender{Reveal: true}}, "sms", true},
		{"no default at all", Router{}, "email", false},
	}
	for _, c := range cases {
		if got := c.r.Configured(c.channel); got != c.want {
			t.Errorf("%s: Configured(%q) = %v, want %v", c.name, c.channel, got, c.want)
		}
	}
}
