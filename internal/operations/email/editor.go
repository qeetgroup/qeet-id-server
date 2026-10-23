package email

import (
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/microcosm-cc/bluemonday"
	htmlparser "golang.org/x/net/html"
	"golang.org/x/text/language"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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

// EmailAppearanceSource returns a tenant's email branding: display name, logo
// URL and primary colour.
type EmailAppearanceSource interface {
	EmailAppearance(context.Context, uuid.UUID) (name, logo, primary string, err error)
}

type templateSource interface {
	Get(context.Context, uuid.UUID, string) (*Resolved, error)
}

// TemplateSender is a notifier.Sender that applies a tenant's customised invite
// or magic-link template before passing the message to Next.
type TemplateSender struct {
	Templates  templateSource
	Appearance EmailAppearanceSource
	Next       notifier.Sender
}

// Send renders the tenant's customised template into message and sends it
// through Next. Other messages, uncustomised templates and render failures are
// sent unchanged.
func (sender TemplateSender) Send(ctx context.Context, message notifier.Message) error {
	if (message.Channel != "" && message.Channel != "email") || (message.TemplateKey != "invite" && message.TemplateKey != "magic_link") {
		return sender.Next.Send(ctx, message)
	}
	tenantID, err := uuid.Parse(message.TenantID)
	if err != nil || tenantID == uuid.Nil {
		return sender.Next.Send(ctx, message)
	}
	template, err := sender.Templates.Get(ctx, tenantID, message.TemplateKey)
	if err != nil || !template.Custom {
		return sender.Next.Send(ctx, message)
	}
	appearance := (&Handler{Appearance: sender.Appearance}).appearance(ctx, tenantID)
	variables := map[string]string{"tenant_name": appearance.name}
	for key, value := range message.TemplateVariables {
		variables[key] = value
	}
	preview, err := renderEditor(message.TemplateKey, EditorInput{Subject: template.Subject, Body: template.Body, Options: template.Options}, variables, "", appearance)
	if err == nil {
		message.Subject, message.Body, message.HTML = preview.Subject, preview.Body, preview.HTML
	}
	return sender.Next.Send(ctx, message)
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

// validateTemplateURLs allows a variable in href or src only as the whole href
// of a *_url variable, so one-time links cannot leak through images or other
// URLs.
func validateTemplateURLs(markup string) error {
	tokenizer := htmlparser.NewTokenizer(strings.NewReader(markup))
	for {
		switch tokenizer.Next() {
		case htmlparser.ErrorToken:
			if errors.Is(tokenizer.Err(), io.EOF) {
				return nil
			}
			return errs.ErrBadRequest.WithDetail("invalid email markup")
		case htmlparser.StartTagToken, htmlparser.SelfClosingTagToken:
			for _, attribute := range tokenizer.Token().Attr {
				if (attribute.Key != "href" && attribute.Key != "src") || !varRe.MatchString(attribute.Val) {
					continue
				}
				match := varRe.FindStringSubmatch(attribute.Val)
				if attribute.Key == "src" || strings.TrimSpace(attribute.Val) != match[0] || !strings.HasSuffix(match[1], "_url") {
					return errs.ErrBadRequest.WithDetail("action variables must be standalone links and cannot be used in images")
				}
			}
		}
	}
}

func normalizeContent(content *LocalizedContent, definition Definition) error {
	content.Subject = strings.TrimSpace(content.Subject)
	content.Body = strings.TrimSpace(content.Body)
	content.Preheader = strings.TrimSpace(content.Preheader)
	if content.Subject == "" || content.Body == "" || utf8.RuneCountInString(content.Subject) > 200 || utf8.RuneCountInString(content.Preheader) > 200 || len(content.Body) > 150000 || len(content.HTML) > 200000 || strings.ContainsAny(content.Subject+content.Preheader, "\r\n") {
		return errs.ErrEmailTemplateContentRequired
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

func (h *Handler) appearance(ctx context.Context, tenantID uuid.UUID) emailAppearance {
	appearance := emailAppearance{name: "Qeet ID", primary: "#f97316"}
	if h.Appearance == nil {
		return appearance
	}
	name, logo, primary, err := h.Appearance.EmailAppearance(ctx, tenantID)
	if err != nil {
		return appearance
	}
	if strings.TrimSpace(name) != "" {
		appearance.name = name
	}
	if emailColor.MatchString(primary) {
		appearance.primary = primary
	}
	if parsed, err := url.Parse(logo); err == nil && parsed.User == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") {
		appearance.logo = logo
	}
	return appearance
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
		return editorPreview{}, errs.ErrEmailTemplateNotFound
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

// testEmail sends a rendered draft to the caller's own verified address, once a
// minute at most. It is forbidden unless TestEmailEnabled is set and a Sender
// is configured.
func (h *Handler) testEmail(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	principal := httpx.PrincipalFromCtx(r.Context())
	if principal == nil || principal.UserID == nil || !h.TestEmailEnabled || h.Sender == nil {
		httpx.WriteError(w, r, errs.ErrForbidden)
		return
	}
	var input struct {
		Draft  EditorInput `json:"draft"`
		Locale string      `json:"locale"`
	}
	if err := httpx.DecodeJSON(r, &input); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var recipient string
	if err := h.Service.pool.QueryRow(r.Context(), `SELECT email FROM "user".users WHERE id=$1 AND email_verified_at IS NOT NULL AND status='active' AND deleted_at IS NULL`, *principal.UserID).Scan(&recipient); err != nil {
		httpx.WriteError(w, r, errs.ErrForbidden)
		return
	}
	parsed, err := mail.ParseAddress(recipient)
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	appearance := h.appearance(r.Context(), tenantID)
	variables := map[string]string{"code": "482913", "ttl": "10 minutes", "tenant_name": appearance.name, "reset_url": "https://example.invalid/test/reset", "magic_url": "https://example.invalid/test/sign-in", "invite_url": "https://example.invalid/test/invite"}
	preview, err := renderEditor(chi.URLParam(r, "key"), input.Draft, variables, input.Locale, appearance)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !h.testLimits.allow(tenantID.String()+":"+principal.UserID.String(), time.Now()) {
		w.Header().Set("Retry-After", "60")
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]any{"code": "rate_limited", "message": "Wait before sending another test email."}})
		return
	}
	tx, err := h.Service.Pool().Begin(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	if err := h.audit(r.Context(), tx, r, tenantID, "email_template.test_requested", chi.URLParam(r, "key")); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Sender.Send(r.Context(), notifier.Message{TenantID: tenantID.String(), Channel: "email", To: parsed.Address, Subject: "[Test] " + preview.Subject, Body: preview.Body, HTML: preview.HTML}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}
