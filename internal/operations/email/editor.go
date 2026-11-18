package email

import (
	"context"
	"errors"
	"html"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/microcosm-cc/bluemonday"
	htmlparser "golang.org/x/net/html"
	"golang.org/x/text/language"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// LocalizedContent is a template's content in one locale.
type LocalizedContent struct {
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	Preheader string `json:"preheader,omitempty"`
	HTML      string `json:"body_html,omitempty"`
}

// EditorOptions are a template's editor settings: HTML body, preheader,
// translations by locale, and header layout.
type EditorOptions struct {
	Preheader     string                      `json:"preheader,omitempty"`
	HTML          string                      `json:"body_html,omitempty"`
	DefaultLocale string                      `json:"default_locale,omitempty"`
	Translations  map[string]LocalizedContent `json:"translations,omitempty"`
	ShowLogo      *bool                       `json:"show_logo,omitempty"`
	Alignment     string                      `json:"alignment,omitempty"`
}

// EditorInput is a template as the editor saves it.
type EditorInput struct {
	Subject string        `json:"subject"`
	Body    string        `json:"body"`
	Options EditorOptions `json:"options"`
}

// EmailAppearanceSource returns an organization's email branding: display name, logo
// URL and primary colour.
type EmailAppearanceSource interface {
	EmailAppearance(context.Context, uuid.UUID) (name, logo, primary string, err error)
}

type templateSource interface {
	Get(context.Context, uuid.UUID, string) (*Resolved, error)
	RecipientLocale(ctx context.Context, organizationID uuid.UUID, address string) (string, error)
}

// TemplateSender is a notifier.Sender that applies an organization's customised invite
// or magic-link template before passing the message to Next.
type TemplateSender struct {
	Templates  templateSource
	Appearance EmailAppearanceSource
	Next       notifier.Sender
}

// Send renders the organization's customised template into message, in the
// recipient's profile language when the template has it and else in the
// template's default locale, and sends it through Next. Other messages,
// uncustomised templates and render failures are sent unchanged.
func (sender TemplateSender) Send(ctx context.Context, message notifier.Message) error {
	if (message.Channel != "" && message.Channel != "email") || (message.TemplateKey != "invite" && message.TemplateKey != "magic_link") {
		return sender.Next.Send(ctx, message)
	}
	organizationID, err := uuid.Parse(message.OrganizationID)
	if err != nil || organizationID == uuid.Nil {
		return sender.Next.Send(ctx, message)
	}
	template, err := sender.Templates.Get(ctx, organizationID, message.TemplateKey)
	if err != nil || !template.Custom {
		return sender.Next.Send(ctx, message)
	}
	appearance := (&Handler{Appearance: sender.Appearance}).appearance(ctx, organizationID)
	variables := map[string]string{"organization_name": appearance.name}
	for key, value := range message.TemplateVariables {
		variables[key] = value
	}
	preferred, err := sender.Templates.RecipientLocale(ctx, organizationID, message.To)
	if err != nil {
		preferred = "" // the template's default locale
	}
	locale := templateLocale(template.Options, preferred)
	preview, err := renderEditor(message.TemplateKey, EditorInput{Subject: template.Subject, Body: template.Body, Options: template.Options}, variables, locale, appearance)
	if err == nil {
		message.Subject, message.Body, message.HTML = preview.Subject, preview.Body, preview.HTML
	}
	return sender.Next.Send(ctx, message)
}

// templateLocale returns the template locale closest to preferred: "en" for
// the base content or a translation's locale. It returns "", the template's
// default locale, when preferred is empty, invalid or matches none closely.
func templateLocale(options EditorOptions, preferred string) string {
	want, err := language.Parse(preferred)
	if preferred == "" || err != nil {
		return ""
	}
	locales := []string{"en"}
	for locale := range options.Translations {
		locales = append(locales, locale)
	}
	slices.Sort(locales[1:])
	tags := make([]language.Tag, len(locales))
	for i, locale := range locales {
		tags[i] = language.Make(locale)
	}
	_, index, confidence := language.NewMatcher(tags).Match(want)
	if confidence < language.High {
		return ""
	}
	return locales[index]
}

type emailAppearance struct{ name, logo, primary string }
type editorPreview struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	HTML    string `json:"html"`
	Locale  string `json:"locale"`
}

var emailHTMLPolicy = bluemonday.UGCPolicy()
var emailColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// sanitizeTemplateHTML strips unsafe markup with bluemonday's UGC policy, while
// keeping {{variable}} placeholders intact.
func sanitizeTemplateHTML(markup string) string {
	prefix := "https://template.invalid/" + uuid.NewString() + "/"
	replacements := []string{}
	protected := varRe.ReplaceAllStringFunc(markup, func(token string) string {
		marker := prefix + uuid.NewString()
		replacements = append(replacements, marker, token)
		return marker
	})
	return strings.NewReplacer(replacements...).Replace(emailHTMLPolicy.Sanitize(protected))
}

// errActionLinkPlacement refuses a one-time link placed anywhere but as a whole
// href, or on a line of its own in the text.
var errActionLinkPlacement = errs.ErrBadRequest.WithDetail("action variables must be standalone links and cannot be used in images or text")

// hasActionVariable reports whether value uses a *_url variable.
func hasActionVariable(value string) bool {
	for _, match := range varRe.FindAllStringSubmatch(value, -1) {
		if strings.HasSuffix(match[1], "_url") {
			return true
		}
	}
	return false
}

// validateTemplateURLs allows a variable in href or src only as the whole href
// of a *_url variable, and a *_url variable nowhere else in the markup, so a
// one-time link can't leak through images or other URLs, or be dressed up in
// the organization's words.
func validateTemplateURLs(markup string) error {
	tokenizer := htmlparser.NewTokenizer(strings.NewReader(markup))
	for {
		switch tokenizer.Next() {
		case htmlparser.ErrorToken:
			if errors.Is(tokenizer.Err(), io.EOF) {
				return nil
			}
			return errs.ErrBadRequest.WithDetail("invalid email markup")
		case htmlparser.TextToken:
			if hasActionVariable(string(tokenizer.Text())) {
				return errActionLinkPlacement
			}
		case htmlparser.StartTagToken, htmlparser.SelfClosingTagToken:
			for _, attribute := range tokenizer.Token().Attr {
				if attribute.Key != "href" && attribute.Key != "src" {
					if hasActionVariable(attribute.Val) {
						return errActionLinkPlacement
					}
					continue
				}
				if !varRe.MatchString(attribute.Val) {
					continue
				}
				match := varRe.FindStringSubmatch(attribute.Val)
				if attribute.Key == "src" || strings.TrimSpace(attribute.Val) != match[0] || !strings.HasSuffix(match[1], "_url") {
					return errActionLinkPlacement
				}
			}
		}
	}
}

// validateTextLinks allows a *_url variable in the text only on a line of its
// own, and never in the subject or preheader.
func validateTextLinks(content LocalizedContent) error {
	if hasActionVariable(content.Subject) || hasActionVariable(content.Preheader) {
		return errActionLinkPlacement
	}
	for _, line := range strings.Split(content.Body, "\n") {
		if line = strings.TrimSpace(line); hasActionVariable(line) && varRe.FindString(line) != line {
			return errActionLinkPlacement
		}
	}
	return nil
}

func normalizeContent(content *LocalizedContent, definition Definition) error {
	content.Subject = strings.TrimSpace(content.Subject)
	content.Body = strings.TrimSpace(content.Body)
	content.Preheader = strings.TrimSpace(content.Preheader)
	if content.Subject == "" || content.Body == "" || utf8.RuneCountInString(content.Subject) > 200 || utf8.RuneCountInString(content.Preheader) > 200 || len(content.Body) > 150000 || len(content.HTML) > 200000 || strings.ContainsAny(content.Subject+content.Preheader, "\r\n") {
		return ErrTemplateContentRequired
	}
	allowed := map[string]bool{}
	for _, name := range definition.Variables {
		allowed[name] = true
	}
	for _, match := range varRe.FindAllStringSubmatch(content.Subject+content.Body+content.Preheader+content.HTML, -1) {
		if !allowed[match[1]] {
			return errs.ErrBadRequest.WithDetail("unsupported template variable")
		}
	}
	content.HTML = sanitizeTemplateHTML(content.HTML)
	if err := validateTemplateURLs(content.HTML); err != nil {
		return err
	}
	if err := validateTextLinks(*content); err != nil {
		return err
	}
	for _, name := range definition.Variables {
		if !strings.HasSuffix(name, "_url") {
			continue
		}
		contains := func(value string) bool {
			for _, match := range varRe.FindAllStringSubmatch(value, -1) {
				if match[1] == name {
					return true
				}
			}
			return false
		}
		if !contains(content.Body) || (content.HTML != "" && !contains(content.HTML)) {
			return errs.ErrBadRequest.WithDetail("template must retain its action URL variable")
		}
	}
	return nil
}

func boundedRender(value string, variables map[string]string) (string, error) {
	size := len(value)
	for _, match := range varRe.FindAllStringSubmatch(value, -1) {
		if replacement, exists := variables[match[1]]; exists {
			size += len(replacement) - len(match[0])
		}
		if size > 200000 {
			return "", errs.ErrBadRequest.WithDetail("rendered template is too large")
		}
	}
	return Render(value, variables), nil
}

func normalizeEditor(input *EditorInput, definition Definition) error {
	base := LocalizedContent{Subject: input.Subject, Body: input.Body, Preheader: input.Options.Preheader, HTML: input.Options.HTML}
	if err := normalizeContent(&base, definition); err != nil {
		return err
	}
	input.Subject, input.Body, input.Options.Preheader, input.Options.HTML = base.Subject, base.Body, base.Preheader, base.HTML
	if input.Options.Alignment == "" {
		input.Options.Alignment = "center"
	}
	if input.Options.Alignment != "left" && input.Options.Alignment != "center" {
		return errs.ErrBadRequest.WithDetail("invalid header alignment")
	}
	if input.Options.DefaultLocale == "" {
		input.Options.DefaultLocale = "en"
	}
	if len(input.Options.Translations) > 20 {
		return errs.ErrBadRequest.WithDetail("too many template translations")
	}
	translations := map[string]LocalizedContent{}
	for locale, content := range input.Options.Translations {
		tag, err := language.Parse(locale)
		if err != nil || tag.String() != locale || locale == "en" || locale == "und" {
			return errs.ErrBadRequest.WithDetail("invalid translation locale")
		}
		if err := normalizeContent(&content, definition); err != nil {
			return err
		}
		translations[locale] = content
	}
	input.Options.Translations = translations
	if input.Options.DefaultLocale != "en" {
		if _, exists := translations[input.Options.DefaultLocale]; !exists {
			return errs.ErrBadRequest.WithDetail("default locale has no translation")
		}
	}
	return nil
}

func renderEditor(key string, input EditorInput, variables map[string]string, locale string, appearance emailAppearance) (editorPreview, error) {
	if len(variables) > 32 {
		return editorPreview{}, errs.ErrBadRequest.WithDetail("too many preview variables")
	}
	for _, value := range variables {
		if len(value) > 4096 {
			return editorPreview{}, errs.ErrBadRequest.WithDetail("preview variable is too long")
		}
	}
	definition, exists := defByKey(key)
	if !exists {
		return editorPreview{}, ErrTemplateNotFound
	}
	if err := normalizeEditor(&input, definition); err != nil {
		return editorPreview{}, err
	}
	if locale == "" {
		locale = input.Options.DefaultLocale
	}
	content := LocalizedContent{Subject: input.Subject, Body: input.Body, Preheader: input.Options.Preheader, HTML: input.Options.HTML}
	if locale != "en" {
		var exists bool
		content, exists = input.Options.Translations[locale]
		if !exists {
			return editorPreview{}, errs.ErrBadRequest.WithDetail("translation not found")
		}
	}
	subject, err := boundedRender(content.Subject, variables)
	if err != nil {
		return editorPreview{}, err
	}
	body, err := boundedRender(content.Body, variables)
	if err != nil {
		return editorPreview{}, err
	}
	result := editorPreview{Subject: subject, Body: body, Locale: locale}
	escaped := map[string]string{}
	for key, value := range variables {
		escaped[key] = html.EscapeString(value)
	}
	renderedHTML, err := boundedRender(content.HTML, escaped)
	if err != nil {
		return editorPreview{}, err
	}
	markup := emailHTMLPolicy.Sanitize(renderedHTML)
	if markup == "" {
		markup = "<p>" + strings.ReplaceAll(html.EscapeString(result.Body), "\n", "<br>") + "</p>"
	}
	brand := html.EscapeString(appearance.name)
	logo := ""
	if appearance.logo != "" && (input.Options.ShowLogo == nil || *input.Options.ShowLogo) {
		logo = `<img src="` + html.EscapeString(appearance.logo) + `" alt="" width="48" style="max-width:100%;height:auto;max-height:64px;object-fit:contain">`
	}
	renderedPreheader, err := boundedRender(content.Preheader, variables)
	if err != nil {
		return editorPreview{}, err
	}
	preheader := html.EscapeString(renderedPreheader)
	result.HTML = `<!doctype html><html lang="` + html.EscapeString(locale) + `"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{margin:0;font-family:Arial,sans-serif;color:#18181b;background:#fafafa}p{line-height:1.65}a{color:` + appearance.primary + `}img{max-width:100%;height:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f5;padding:12px}blockquote{border-left:3px solid ` + appearance.primary + `;margin:12px 0;padding-left:12px}table{max-width:100%;width:100%}</style></head><body><div style="display:none;max-height:0;overflow:hidden">` + preheader + `</div><table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="padding:16px"><div style="max-width:560px;margin:auto;background:white;border:1px solid #e4e4e7;border-radius:6px;overflow:hidden"><div style="padding:20px;background:` + appearance.primary + `0d;border-top:3px solid ` + appearance.primary + `;text-align:` + input.Options.Alignment + `">` + logo + `<div style="font-weight:700;margin-top:8px">` + brand + `</div></div><div style="padding:24px;overflow-wrap:anywhere"><h1 style="font-size:20px;line-height:1.4;margin:0 0 18px">` + html.EscapeString(result.Subject) + `</h1>` + markup + `</div><div style="padding:14px;text-align:center;border-top:1px solid #f4f4f5;font-size:11px;color:#71717a">` + brand + `</div></div></td></tr></table></body></html>`
	return result, nil
}

// testEmailLimits allows each key one test email a minute. It is safe for
// concurrent use.
type testEmailLimits struct {
	mutex   sync.Mutex
	entries map[string]time.Time
}

func (limit *testEmailLimits) allow(key string, now time.Time) bool {
	limit.mutex.Lock()
	defer limit.mutex.Unlock()
	if limit.entries == nil {
		limit.entries = map[string]time.Time{}
	}
	for entry, expires := range limit.entries {
		if !expires.After(now) {
			delete(limit.entries, entry)
		}
	}
	if limit.entries[key].After(now) {
		return false
	}
	limit.entries[key] = now.Add(time.Minute)
	return true
}
