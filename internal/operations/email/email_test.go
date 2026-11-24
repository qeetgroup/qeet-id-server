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
	if !limits.allow("organization-a:user-a", now) || limits.allow("organization-a:user-a", now) {
		t.Fatal("test email rate limit not enforced")
	}
	if !limits.allow("organization-b:user-a", now) || !limits.allow("organization-a:user-a", now.Add(time.Minute)) {
		t.Fatal("rate limit not scoped or expiring")
	}
}

type templateFixture struct {
	organization uuid.UUID
	key          string
	calls        int
}

func (fixture *templateFixture) Get(_ context.Context, organizationID uuid.UUID, key string) (*Resolved, error) {
	fixture.organization, fixture.key = organizationID, key
	fixture.calls++
	return &Resolved{Key: key, Subject: "Custom sign-in", Body: "Use this link:\n{{magic_url}}", Options: EditorOptions{HTML: `<p><strong>Use</strong> <a href="{{magic_url}}">Sign in</a></p>`}, Custom: true}, nil
}

func (fixture *templateFixture) RecipientLocale(context.Context, uuid.UUID, string) (string, error) {
	return "", nil
}

// localizedTemplates serves a custom magic-link template with a French
// translation, and each recipient's profile locale by address.
type localizedTemplates struct {
	defaultLocale string
	locales       map[string]string
}

func (templates localizedTemplates) Get(_ context.Context, _ uuid.UUID, key string) (*Resolved, error) {
	return &Resolved{Key: key, Custom: true, Subject: "Sign in", Body: "Use this link:\n{{magic_url}}", Options: EditorOptions{
		DefaultLocale: templates.defaultLocale,
		Translations:  map[string]LocalizedContent{"fr": {Subject: "Connexion", Body: "Utilisez ce lien :\n{{magic_url}}"}},
	}}, nil
}

func (templates localizedTemplates) RecipientLocale(_ context.Context, _ uuid.UUID, address string) (string, error) {
	return templates.locales[address], nil
}

// TestTemplateSenderUsesRecipientLocale checks that a customised email is
// rendered in the recipient's profile language when the template has it, and
// otherwise in the template's default locale.
func TestTemplateSenderUsesRecipientLocale(t *testing.T) {
	locales := map[string]string{"anne@example.test": "fr", "dirk@example.test": "de", "emma@example.test": "en"}
	for _, test := range []struct {
		to, defaultLocale, subject string
	}{
		{"anne@example.test", "en", "Connexion"},   // French profile, French translation
		{"dirk@example.test", "en", "Sign in"},     // German profile, no German translation
		{"dirk@example.test", "fr", "Connexion"},   // ... so the organization's default
		{"emma@example.test", "fr", "Sign in"},     // English profile, the base content
		{"nobody@example.test", "fr", "Connexion"}, // no account: the organization's default
	} {
		sink := &emailSink{}
		sender := TemplateSender{Templates: localizedTemplates{defaultLocale: test.defaultLocale, locales: locales}, Next: sink}
		message := notifier.Message{OrganizationID: uuid.NewString(), Channel: "email", To: test.to, TemplateKey: "magic_link", TemplateVariables: map[string]string{"magic_url": "https://example.test/once"}, Subject: "Original", Body: "Original"}
		if err := sender.Send(context.Background(), message); err != nil {
			t.Fatal(err)
		}
		if sink.last.Subject != test.subject {
			t.Errorf("to %s with default %s: subject = %q, want %q", test.to, test.defaultLocale, sink.last.Subject, test.subject)
		}
	}
}

func TestTemplateLocale(t *testing.T) {
	options := EditorOptions{Translations: map[string]LocalizedContent{"fr": {}, "pt-BR": {}, "zh-Hant": {}}}
	for preferred, want := range map[string]string{
		"":      "",
		"fr":    "fr",
		"fr-CA": "fr",
		"pt":    "pt-BR",
		"en":    "en",
		"de":    "",
		"zh":    "",
		"!":     "",
	} {
		if got := templateLocale(options, preferred); got != want {
			t.Errorf("templateLocale(%q) = %q, want %q", preferred, got, want)
		}
	}
}

type emailSink struct{ last notifier.Message }

func (sink *emailSink) Send(_ context.Context, message notifier.Message) error {
	sink.last = message
	return nil
}

// TestTemplateSenderScope checks which messages get an organization's template.
func TestTemplateSenderScope(t *testing.T) {
	organizationID := uuid.New()
	templates := &templateFixture{}
	sink := &emailSink{}
	sender := TemplateSender{Templates: templates, Next: sink}
	message := notifier.Message{OrganizationID: organizationID.String(), Channel: "email", TemplateKey: "magic_link", TemplateVariables: map[string]string{"magic_url": "https://example.test/once"}, Subject: "Original", Body: "Original"}
	if err := sender.Send(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if templates.organization != organizationID || sink.last.Subject != "Custom sign-in" || !strings.Contains(sink.last.HTML, "https://example.test/once") {
		t.Fatal("scoped template not applied")
	}
	for _, key := range []string{"verify_email", "password_reset", "mfa_otp", "invite"} {
		calls := templates.calls
		if err := sender.Send(context.Background(), notifier.Message{OrganizationID: organizationID.String(), Channel: "email", TemplateKey: key, Subject: "Platform"}); err != nil {
			t.Fatal(err)
		}
		if templates.calls != calls+1 || templates.key != key {
			t.Errorf("%s: the organization's template was not looked up", key)
		}
	}
	calls := templates.calls
	for _, message := range []notifier.Message{
		{TemplateKey: "magic_link", Subject: "Platform"},
		{OrganizationID: uuid.Nil.String(), TemplateKey: "password_reset", Subject: "Platform"},
		{OrganizationID: organizationID.String(), TemplateKey: "account_notice", Subject: "Platform"},
		{OrganizationID: organizationID.String(), Channel: "sms", TemplateKey: "mfa_otp", Subject: "Platform"},
	} {
		if err := sender.Send(context.Background(), message); err != nil {
			t.Fatal(err)
		}
		if sink.last.Subject != "Platform" || templates.calls != calls {
			t.Errorf("%+v: sent as %q after %d lookups, want the platform's wording unlooked-up", message, sink.last.Subject, templates.calls-calls)
		}
	}
}

// TestCodeTemplatesKeepTheirCode checks that a code template must keep {{code}}.
func TestCodeTemplatesKeepTheirCode(t *testing.T) {
	for _, key := range []string{"verify_email", "mfa_otp"} {
		d, _ := defByKey(key)
		for name, input := range map[string]EditorInput{
			"no code in the text": {Subject: "Your code", Body: "Enter the code we sent."},
			"no code in the HTML": {Subject: "Your code", Body: "Your code is {{code}}.", Options: EditorOptions{HTML: "<p>Enter the code we sent.</p>"}},
			"code only in a translation": {Subject: "Your code", Body: "Enter it.", Options: EditorOptions{
				Translations: map[string]LocalizedContent{"fr": {Subject: "Votre code", Body: "Votre code est {{code}}."}}}},
		} {
			if err := normalizeEditor(&input, d); err == nil {
				t.Errorf("%s with %s: accepted", key, name)
			}
		}
		kept := EditorInput{Subject: "Your code", Body: "Your code is {{code}}. It expires in {{ttl}}.", Options: EditorOptions{HTML: "<p><strong>{{code}}</strong></p>"}}
		if err := normalizeEditor(&kept, d); err != nil {
			t.Errorf("%s with its code: %v", key, err)
		}
	}
}

func TestTemplateLinksPreserveVariablesAndSanitizeResolvedURLs(t *testing.T) {
	input := EditorInput{Subject: "Sign in", Body: "Use this link:\n{{magic_url}}", Options: EditorOptions{HTML: `<p><a href="{{magic_url}}">Continue</a></p>`}}
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

// TestActionURLOnlyInHref checks that a template may carry its one-time link
// only as a whole href in the HTML and on a line of its own in the text, never
// in the subject, the preheader or among the words, so an organization's
// wording can't dress the link up as something else.
func TestActionURLOnlyInHref(t *testing.T) {
	standalone := EditorInput{Subject: "Sign in", Body: "Use the link below to sign in.\n\n{{magic_url}}\n\nIt works once.",
		Options: EditorOptions{HTML: `<p>Use the button below.</p><p><a href="{{magic_url}}">Sign in</a></p>`}}
	if err := normalizeEditor(&standalone, catalog[2]); err != nil {
		t.Errorf("the link on its own line and as a whole href: %v, want it accepted", err)
	}
	for name, input := range map[string]EditorInput{
		"among the text's words":  {Subject: "Sign in", Body: "Claim your prize at {{magic_url}} today"},
		"in the subject":          {Subject: "Sign in at {{magic_url}}", Body: "{{magic_url}}"},
		"in the preheader":        {Subject: "Sign in", Body: "{{magic_url}}", Options: EditorOptions{Preheader: "Open {{magic_url}}"}},
		"among the HTML's words":  {Subject: "Sign in", Body: "{{magic_url}}", Options: EditorOptions{HTML: `<p>Claim your prize at {{magic_url}}</p><a href="{{magic_url}}">Sign in</a>`}},
		"in a translation's text": {Subject: "Sign in", Body: "{{magic_url}}", Options: EditorOptions{Translations: map[string]LocalizedContent{"fr": {Subject: "Connexion", Body: "Gagnez sur {{magic_url}}"}}}},
	} {
		if err := normalizeEditor(&input, catalog[2]); err == nil {
			t.Errorf("the link %s was accepted", name)
		}
	}
	titled := EditorInput{Subject: "Sign in", Body: "{{magic_url}}", Options: EditorOptions{HTML: `<a href="{{magic_url}}" title="{{magic_url}}">Sign in</a>`}}
	if err := normalizeEditor(&titled, catalog[2]); err != nil || strings.Count(titled.Options.HTML, "{{magic_url}}") != 1 {
		t.Errorf("the link in another attribute: %v, %q; want that attribute dropped", err, titled.Options.HTML)
	}
	for _, d := range catalog {
		if err := normalizeEditor(&EditorInput{Subject: d.DefaultSubject, Body: d.DefaultBody}, d); err != nil {
			t.Errorf("the %s default can't be saved unchanged: %v", d.Key, err)
		}
	}
}
