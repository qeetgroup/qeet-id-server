package branding

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestBackgroundSetting(t *testing.T) {
	brand := Branding{Settings: map[string]any{"background_color": " #FAFAFA ", "existing": "preserved"}}
	if err := normalizeAppearance(&brand); err != nil {
		t.Fatal(err)
	}
	_, _, _, background := loginAppearance(&brand)
	if background != "#fafafa" || brand.Settings["existing"] != "preserved" {
		t.Fatalf("unexpected appearance: %q", background)
	}
	for _, invalid := range []any{23, nil, "red", "#12345678", "url(https://example.test)"} {
		if err := normalizeAppearance(&Branding{Settings: map[string]any{"background_color": invalid}}); err == nil {
			t.Errorf("accepted invalid background %v", invalid)
		}
	}
}

func TestBrandingUploadLimit(t *testing.T) {
	logo := "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, 2<<20))
	body, err := json.Marshal(Branding{LogoURL: &logo, Settings: map[string]any{"background_color": "#ffffff"}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("PUT", "/branding", strings.NewReader(string(body)))
	parsed, err := decodeBranding(request)
	if err != nil || parsed.LogoURL == nil || *parsed.LogoURL != logo {
		t.Fatalf("2 MB logo rejected: %v", err)
	}
	oversized := "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, (2<<20)+1))
	if err := normalizeAppearance(&Branding{LogoURL: &oversized}); !errors.Is(err, errs.ErrRequestBodyTooLarge) {
		t.Fatalf("oversized logo result: %v", err)
	}
	body, err = json.Marshal(Branding{Settings: map[string]any{"extra": strings.Repeat("x", int(maxBrandingBodyBytes))}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeBranding(httptest.NewRequest("PUT", "/branding", strings.NewReader(string(body))))
	if !errors.Is(err, errs.ErrRequestBodyTooLarge) {
		t.Fatalf("request limit not enforced: %v", err)
	}
}

func TestBackgroundUnsetAndLegacy(t *testing.T) {
	for _, settings := range []map[string]any{nil, {}, {"background_color": ""}, {"background_color": "invalid"}} {
		_, _, _, background := loginAppearance(&Branding{Settings: settings})
		if background != "" {
			t.Errorf("unexpected background override %q", background)
		}
	}
}

func TestReplyToValidation(t *testing.T) {
	for _, value := range []any{"not-email", "Name <mail@example.test>", "mail@example.test\r\nBcc: other@example.test", 42} {
		if err := normalizeAppearance(&Branding{Settings: map[string]any{"email_reply_to": value}}); err == nil {
			t.Errorf("accepted invalid reply-to %v", value)
		}
	}
	brand := Branding{Settings: map[string]any{"email_reply_to": " support@example.test "}}
	if err := normalizeAppearance(&brand); err != nil || brand.Settings["email_reply_to"] != "support@example.test" {
		t.Fatalf("valid reply-to rejected: %v", err)
	}
}

type identityFixture struct {
	tenant uuid.UUID
	err    error
}

func (source *identityFixture) EmailIdentity(_ context.Context, tenant uuid.UUID) (string, string, error) {
	source.tenant = tenant
	return "Tenant name", "support@example.test", source.err
}

type notificationFixture struct{ message notifier.Message }

func (sink *notificationFixture) Send(_ context.Context, message notifier.Message) error {
	sink.message = message
	return nil
}

func TestSenderUsesOnlyExplicitTenant(t *testing.T) {
	tenant := uuid.New()
	source := &identityFixture{}
	sink := &notificationFixture{}
	sender := Sender{Source: source, Next: sink}
	if err := sender.Send(context.Background(), notifier.Message{TenantID: tenant.String(), Channel: "email"}); err != nil {
		t.Fatal(err)
	}
	if source.tenant != tenant || sink.message.FromName != "Tenant name" || sink.message.ReplyTo != "support@example.test" {
		t.Fatal("tenant identity not applied")
	}
	for _, message := range []notifier.Message{{Channel: "email"}, {TenantID: "invalid", Channel: "email"}, {TenantID: tenant.String(), Channel: "sms"}} {
		source.tenant = uuid.Nil
		if err := sender.Send(context.Background(), message); err != nil {
			t.Fatal(err)
		}
		if source.tenant != uuid.Nil || sink.message.FromName != "" || sink.message.ReplyTo != "" {
			t.Fatal("branding applied outside tenant email")
		}
	}
	source.err = errors.New("unavailable")
	if err := sender.Send(context.Background(), notifier.Message{TenantID: tenant.String(), Channel: "email"}); err != nil {
		t.Fatal(err)
	}
	if sink.message.FromName != "" || sink.message.ReplyTo != "" {
		t.Fatal("failed lookup must keep platform identity")
	}
}
