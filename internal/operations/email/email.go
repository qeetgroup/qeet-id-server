// Package email manages per-organization transactional email templates. The catalog of
// known templates and their default subject/body lives in code; organizations store
// only overrides. Render substitutes {{variable}} placeholders.
package email

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Definition is a catalog entry: a known template key with its built-in
// default content and the variables it understands.
type Definition struct {
	Key            string
	Name           string
	Description    string
	DefaultSubject string
	DefaultBody    string
	Variables      []string
}

// catalog lists the transactional emails the platform sends, with their
// defaults.
var catalog = []Definition{
	{
		Key: "verify_email", Name: "Email verification",
		Description:    "Sent when a user verifies their email address.",
		DefaultSubject: "Verify your email",
		DefaultBody:    "Your verification code is {{code}}. It expires in {{ttl}}.",
		Variables:      []string{"code", "ttl"},
	},
	{
		Key: "password_reset", Name: "Password reset",
		Description:    "Sent when a user requests a password reset.",
		DefaultSubject: "Reset your password",
		DefaultBody:    "Click to reset your password:\n{{reset_url}}",
		Variables:      []string{"reset_url"},
	},
	{
		Key: "magic_link", Name: "Magic link",
		Description:    "A passwordless one-time sign-in link.",
		DefaultSubject: "Your login link",
		DefaultBody:    "Click to sign in:\n{{magic_url}}",
		Variables:      []string{"magic_url"},
	},
	{
		Key: "invite", Name: "Invitation",
		Description:    "Sent when a member is invited to an organization.",
		DefaultSubject: "You've been invited to {{organization_name}}",
		DefaultBody:    "Accept your invitation:\n{{invite_url}}",
		Variables:      []string{"organization_name", "invite_url"},
	},
	{
		Key: "mfa_otp", Name: "MFA one-time passcode",
		Description:    "A second-factor code delivered by email or SMS.",
		DefaultSubject: "Your verification code",
		DefaultBody:    "Your sign-in code is {{code}}. It expires in {{ttl}}.",
		Variables:      []string{"code", "ttl"},
	},
}

func defByKey(key string) (Definition, bool) {
	for _, d := range catalog {
		if d.Key == key {
			return d, true
		}
	}
	return Definition{}, false
}

// Resolved is a template as the API shows it: its catalog entry merged with any
// organization override. DeliveryScope is "organization" for templates sent with the
// organization's customisation (invite, magic_link), else "platform".
type Resolved struct {
	Key           string        `json:"key"`
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	Subject       string        `json:"subject"`
	Body          string        `json:"body"`
	Variables     []string      `json:"variables"`
	Custom        bool          `json:"custom"`
	Options       EditorOptions `json:"options"`
	DeliveryScope string        `json:"delivery_scope"`
}

func resolve(d Definition, subject, body *string) Resolved {
	r := Resolved{
		Key: d.Key, Name: d.Name, Description: d.Description,
		Subject: d.DefaultSubject, Body: d.DefaultBody, Variables: d.Variables,
		DeliveryScope: "platform",
	}
	if d.Key == "invite" || d.Key == "magic_link" {
		r.DeliveryScope = "organization"
	}
	if subject != nil && body != nil {
		r.Subject, r.Body, r.Custom = *subject, *body, true
	}
	return r
}

var varRe = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

// Render substitutes {{name}} placeholders from vars. Unknown placeholders are
// left as they are, so a missing value shows rather than vanishing.
func Render(s string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		key := strings.Trim(strings.TrimSpace(m), "{} ")
		if v, ok := vars[key]; ok {
			return v
		}
		return m
	})
}

// Service stores organizations' email template overrides.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns a Service over pool.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// overrides returns the organization's customised templates by template key.
func (s *Service) overrides(ctx context.Context, organizationID uuid.UUID) (map[string]dbgen.ListEmailTemplateOverridesRow, error) {
	rows, err := s.q.ListEmailTemplateOverrides(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := map[string]dbgen.ListEmailTemplateOverridesRow{}
	for _, r := range rows {
		out[r.TemplateKey] = r
	}
	return out, nil
}

// List returns every catalog template, with the organization's overrides applied.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Resolved, error) {
	ov, err := s.overrides(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Resolved, 0, len(catalog))
	for _, d := range catalog {
		if o, ok := ov[d.Key]; ok {
			resolved := resolve(d, &o.Subject, &o.Body)
			if err := json.Unmarshal(o.Options, &resolved.Options); err != nil {
				return nil, err
			}
			out = append(out, resolved)
		} else {
			out = append(out, resolve(d, nil, nil))
		}
	}
	return out, nil
}

// Get returns one template with the organization's override applied. An unknown key
// returns ErrTemplateNotFound.
func (s *Service) Get(ctx context.Context, organizationID uuid.UUID, key string) (*Resolved, error) {
	d, ok := defByKey(key)
	if !ok {
		return nil, ErrTemplateNotFound
	}
	row, err := s.q.GetEmailTemplateOverride(ctx, dbgen.GetEmailTemplateOverrideParams{
		OrganizationID: organizationID, TemplateKey: key,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		r := resolve(d, nil, nil)
		return &r, nil
	}
	if err != nil {
		return nil, err
	}
	r := resolve(d, &row.Subject, &row.Body)
	if err := json.Unmarshal(row.Options, &r.Options); err != nil {
		return nil, err
	}
	return &r, nil
}

// RecipientLocale returns the profile language of the account at address, or ""
// when it has none or doesn't belong to the organization.
func (s *Service) RecipientLocale(ctx context.Context, organizationID uuid.UUID, address string) (string, error) {
	locale, err := s.q.GetRecipientLocale(ctx, dbgen.GetRecipientLocaleParams{OrganizationID: organizationID, Email: address})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return locale, err
}

// UpsertEditor validates input and saves it as the organization's override of a
// template, recorded as actor's in the same transaction.
func (s *Service) UpsertEditor(ctx context.Context, organizationID uuid.UUID, key string, input EditorInput, actor audit.Actor) (*Resolved, error) {
	d, ok := defByKey(key)
	if !ok {
		return nil, ErrTemplateNotFound
	}
	if err := normalizeEditor(&input, d); err != nil {
		return nil, err
	}
	options, err := json.Marshal(input.Options)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.q.WithTx(tx).UpsertEmailTemplate(ctx, dbgen.UpsertEmailTemplateParams{
		OrganizationID: organizationID, TemplateKey: key, Subject: input.Subject, Body: input.Body, Options: options,
	}); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, templateEvent(actor, organizationID, "email_template.updated", key)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	r := resolve(d, &input.Subject, &input.Body)
	r.Options = input.Options
	return &r, nil
}

// Reset deletes the organization's override of a template, restoring the
// built-in default, recorded as actor's in the same transaction.
func (s *Service) Reset(ctx context.Context, organizationID uuid.UUID, key string, actor audit.Actor) (*Resolved, error) {
	d, ok := defByKey(key)
	if !ok {
		return nil, ErrTemplateNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.q.WithTx(tx).DeleteEmailTemplate(ctx, dbgen.DeleteEmailTemplateParams{
		OrganizationID: organizationID, TemplateKey: key,
	}); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, templateEvent(actor, organizationID, "email_template.reset", key)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	r := resolve(d, nil, nil)
	return &r, nil
}

// VerifiedAddress is the verified email address of the active account
// userID, where a test email of its own may go.
func (s *Service) VerifiedAddress(ctx context.Context, userID uuid.UUID) (string, error) {
	return s.q.GetVerifiedEmail(ctx, userID)
}

// RecordTestRequested records that actor asked for a test send of the
// template key: an event of its own, as no change commits with it.
func (s *Service) RecordTestRequested(ctx context.Context, organizationID uuid.UUID, key string, actor audit.Actor) error {
	return audit.RecordAlone(ctx, s.pool, templateEvent(actor, organizationID, "email_template.test_requested", key))
}

// templateEvent is the audit event of action on the organization's template key.
func templateEvent(actor audit.Actor, organizationID uuid.UUID, action, key string) audit.Event {
	return actor.Event(organizationID, action, "email_template", uuid.Nil, map[string]any{"template_key": key})
}

// templateList is every template, with what the editor can do.
type templateList struct {
	paging.Result[Resolved]
	Capabilities map[string]bool `json:"capabilities"`
}
