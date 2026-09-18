package email

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestRender(t *testing.T) {
	vars := map[string]string{"code": "123456", "ttl": "10m"}
	if got := Render("Your code is {{code}}, valid {{ttl}}.", vars); got != "Your code is 123456, valid 10m." {
		t.Errorf("substitution failed: %q", got)
	}
	// Spaces inside braces are tolerated.
	if got := Render("{{ code }}", vars); got != "123456" {
		t.Errorf("whitespace handling failed: %q", got)
	}
	// Unknown placeholders are left intact (visible, not blanked).
	if got := Render("Hi {{name}}", vars); got != "Hi {{name}}" {
		t.Errorf("unknown placeholder should be preserved: %q", got)
	}
	// No placeholders → unchanged.
	if got := Render("plain text", vars); got != "plain text" {
		t.Errorf("plain text changed: %q", got)
	}
}

func TestCatalogResolve(t *testing.T) {
	d, ok := defByKey("verify_email")
	if !ok {
		t.Fatal("verify_email must be in the catalog")
	}
	// No override → default, not custom.
	def := resolve(d, nil, nil)
	if def.Custom || def.Subject != d.DefaultSubject {
		t.Errorf("default resolve wrong: %+v", def)
	}
	// Override → custom content.
	subj, body := "Custom subject", "Custom body {{code}}"
	ov := resolve(d, &subj, &body)
	if !ov.Custom || ov.Subject != subj || ov.Body != body {
		t.Errorf("override resolve wrong: %+v", ov)
	}
	if _, ok := defByKey("nope"); ok {
		t.Error("unknown key should not resolve")
	}
}

func TestEditorSanitizesMarkup(t *testing.T) {
	input := EditorInput{Subject: "Code {{code}}", Body: "Use {{code}}", Options: EditorOptions{HTML: `<p onclick="steal()">{{code}}</p><script>steal()</script><a href="javascript:steal()">bad</a><img src="https://example.test/logo.png" onerror="steal()">`, Preheader: "Code expires in {{ttl}}"}}
	preview, err := renderEditor("verify_email", input, map[string]string{"code": `<img src=x onerror=steal()>`, "ttl": "10 minutes"}, "en", emailAppearance{name: "Qeet <Team>", primary: "#f97316"})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"<script", `onclick=`, `javascript:`, `onerror="`, "Qeet <Team>"} {
		if strings.Contains(preview.HTML, forbidden) {
			t.Errorf("unsafe markup survived: %s", forbidden)
		}
	}
	if !strings.Contains(preview.HTML, "Qeet &lt;Team&gt;") || !strings.Contains(preview.HTML, "#f97316") {
		t.Fatal("brand not applied safely")
	}
}

func TestEditorLocalesAndPlainText(t *testing.T) {
	input := EditorInput{Subject: "Your code", Body: "Code {{code}}", Options: EditorOptions{DefaultLocale: "fr", Translations: map[string]LocalizedContent{"fr": {Subject: "Votre code", Body: "Code {{code}}", Preheader: "Expire dans {{ttl}}"}}}}
	preview, err := renderEditor("verify_email", input, map[string]string{"code": "123456", "ttl": "10 minutes"}, "", emailAppearance{name: "Qeet ID", primary: "#f97316"})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Subject != "Votre code" || preview.Body != "Code 123456" || preview.Locale != "fr" {
		t.Fatalf("wrong localized preview: %+v", preview)
	}
	if !strings.Contains(preview.HTML, "Expire dans 10 minutes") {
		t.Fatal("preheader omitted")
	}
	if _, err := renderEditor("verify_email", input, nil, "de", emailAppearance{}); err == nil {
		t.Fatal("missing locale accepted")
	}
	input.Options.DefaultLocale = "de"
	if err := normalizeEditor(&input, catalog[0]); err == nil {
		t.Fatal("unknown default locale accepted")
	}
}

func TestEditorRejectsInvalidContent(t *testing.T) {
	for _, input := range []EditorInput{
		{Subject: "", Body: "body"},
		{Subject: "Subject\r\nBcc: other@example.test", Body: "body"},
		{Subject: "{{unknown}}", Body: "body"},
		{Subject: "subject", Body: "body", Options: EditorOptions{Preheader: strings.Repeat("x", 201)}},
		{Subject: "subject", Body: "body", Options: EditorOptions{Alignment: "expression(alert())"}},
		{Subject: "subject", Body: "body", Options: EditorOptions{Translations: map[string]LocalizedContent{"invalid_locale!": {Subject: "subject", Body: "body"}}}},
	} {
		if err := normalizeEditor(&input, catalog[0]); err == nil {
			t.Fatalf("invalid content accepted: %+v", input)
		}
	}
}

func TestEmailTestThrottle(t *testing.T) {
	var limits testEmailLimits
	now := time.Now()
	if !limits.allow("tenant-a:user-a", now) || limits.allow("tenant-a:user-a", now) {
		t.Fatal("test email rate limit not enforced")
	}
	if !limits.allow("tenant-b:user-a", now) || !limits.allow("tenant-a:user-a", now.Add(time.Minute)) {
		t.Fatal("rate limit not scoped or expiring")
	}
}

type templateFixture struct {
	tenant uuid.UUID
	calls  int
}

func (fixture *templateFixture) Get(_ context.Context, tenantID uuid.UUID, key string) (*Resolved, error) {
	fixture.tenant = tenantID
	fixture.calls++
	return &Resolved{Key: key, Subject: "Custom sign-in", Body: "Use {{magic_url}}", Options: EditorOptions{HTML: `<p><strong>Use</strong> <a href="{{magic_url}}">Sign in</a></p>`}, Custom: true}, nil
}

type emailSink struct{ last notifier.Message }

func (sink *emailSink) Send(_ context.Context, message notifier.Message) error {
	sink.last = message
	return nil
}

func TestTemplateSenderScope(t *testing.T) {
	tenantID := uuid.New()
	templates := &templateFixture{}
	sink := &emailSink{}
	sender := TemplateSender{Templates: templates, Next: sink}
	message := notifier.Message{TenantID: tenantID.String(), Channel: "email", TemplateKey: "magic_link", TemplateVariables: map[string]string{"magic_url": "https://example.test/once"}, Subject: "Original", Body: "Original"}
	if err := sender.Send(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if templates.tenant != tenantID || sink.last.Subject != "Custom sign-in" || !strings.Contains(sink.last.HTML, "https://example.test/once") {
		t.Fatal("scoped template not applied")
	}
	for _, message := range []notifier.Message{{TemplateKey: "magic_link", Subject: "Platform"}, {TenantID: tenantID.String(), TemplateKey: "password_reset", Subject: "Platform"}, {TenantID: tenantID.String(), Channel: "sms", TemplateKey: "magic_link", Subject: "Platform"}} {
		if err := sender.Send(context.Background(), message); err != nil {
			t.Fatal(err)
		}
		if sink.last.Subject != "Platform" || templates.calls != 1 {
			t.Fatal("platform security email was overridden")
		}
	}
}

func TestTemplateLinksPreserveVariablesAndSanitizeResolvedURLs(t *testing.T) {
	input := EditorInput{Subject: "Sign in", Body: "Use {{magic_url}}", Options: EditorOptions{HTML: `<p><a href="{{magic_url}}">Continue</a></p>`}}
	if err := normalizeEditor(&input, catalog[2]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(input.Options.HTML, `href="{{magic_url}}"`) {
		t.Fatal("link variable was removed")
	}
	preview, err := renderEditor("magic_link", input, map[string]string{"magic_url": "javascript:alert(1)"}, "en", emailAppearance{name: "Qeet ID", primary: "#f97316"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(preview.HTML, "javascript:") {
		t.Fatal("resolved unsafe link survived sanitization")
	}
}

func TestEditorActionLinksAndRenderBounds(t *testing.T) {
	missing := EditorInput{Subject: "Sign in", Body: "No link", Options: EditorOptions{HTML: "<p>No link</p>"}}
	if err := normalizeEditor(&missing, catalog[2]); err == nil {
		t.Fatal("action link could be omitted")
	}
	tooLarge := EditorInput{Subject: "Code", Body: strings.Repeat("{{code}}", 1000)}
	if _, err := renderEditor("verify_email", tooLarge, map[string]string{"code": strings.Repeat("x", 1000)}, "en", emailAppearance{}); err == nil {
		t.Fatal("unbounded expansion accepted")
	}
	unicodeSubject := EditorInput{Subject: strings.Repeat("\u8a9e", 200), Body: "Code {{code}}"}
	if err := normalizeEditor(&unicodeSubject, catalog[0]); err != nil {
		t.Fatalf("Unicode character limit treated as bytes: %v", err)
	}
}

func TestActionVariablesCannotLeakThroughExternalAssets(t *testing.T) {
	for _, markup := range []string{`<img src="https://example.test/pixel?token={{magic_url}}"><a href="{{magic_url}}">Sign in</a>`, `<a href="https://example.test/collect?token={{magic_url}}">Sign in</a>`} {
		input := EditorInput{Subject: "Sign in", Body: "{{magic_url}}", Options: EditorOptions{HTML: markup}}
		if err := normalizeEditor(&input, catalog[2]); err == nil {
			t.Fatal("credential-bearing external URL was accepted")
		}
	}
}
