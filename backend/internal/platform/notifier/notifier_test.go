package notifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	msg := string(buildMIME("Qeet <no-reply@q.test>", "u@x.test", "Hi there", "Body line"))
	for _, want := range []string{"From: Qeet <no-reply@q.test>", "To: u@x.test", "Subject: Hi there", "text/plain", "Body line"} {
		if !strings.Contains(msg, want) {
			t.Errorf("MIME missing %q in:\n%s", want, msg)
		}
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
