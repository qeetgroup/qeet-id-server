// Package email manages per-tenant transactional email templates. The catalog of
// known templates and their default subject/body lives in code; tenants store
// only overrides. Render substitutes {{variable}} placeholders.
package email

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/email/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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

// catalog mirrors the transactional emails the platform sends today.
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
		DefaultBody:    "Click to reset your password: {{reset_url}}",
		Variables:      []string{"reset_url"},
	},
	{
		Key: "magic_link", Name: "Magic link",
		Description:    "A passwordless one-time sign-in link.",
		DefaultSubject: "Your login link",
		DefaultBody:    "Click to sign in: {{magic_url}}",
		Variables:      []string{"magic_url"},
	},
	{
		Key: "invite", Name: "Invitation",
		Description:    "Sent when a member is invited to a tenant.",
		DefaultSubject: "You've been invited to {{tenant_name}}",
		DefaultBody:    "Accept your invitation: {{invite_url}}",
		Variables:      []string{"tenant_name", "invite_url"},
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

// Resolved is the API view: catalog metadata merged with any tenant override.
type Resolved struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	Variables   []string `json:"variables"`
	Custom      bool     `json:"custom"`
}

func resolve(d Definition, subject, body *string) Resolved {
	r := Resolved{
		Key: d.Key, Name: d.Name, Description: d.Description,
		Subject: d.DefaultSubject, Body: d.DefaultBody, Variables: d.Variables,
	}
	if subject != nil && body != nil {
		r.Subject, r.Body, r.Custom = *subject, *body, true
	}
	return r
}

var varRe = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

// Render substitutes {{name}} placeholders from vars. Unknown placeholders are
// left intact so a missing value is visible rather than silently blanked.
func Render(s string, vars map[string]string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		key := strings.Trim(strings.TrimSpace(m), "{} ")
		if v, ok := vars[key]; ok {
			return v
		}
		return m
	})
}

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// overrides returns the tenant's customised templates keyed by template_key.
func (s *Service) overrides(ctx context.Context, tenantID uuid.UUID) (map[string][2]string, error) {
	rows, err := s.q.ListEmailTemplateOverrides(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := map[string][2]string{}
	for _, r := range rows {
		out[r.TemplateKey] = [2]string{r.Subject, r.Body}
	}
	return out, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Resolved, error) {
	ov, err := s.overrides(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Resolved, 0, len(catalog))
	for _, d := range catalog {
		if o, ok := ov[d.Key]; ok {
			subj, body := o[0], o[1]
			out = append(out, resolve(d, &subj, &body))
		} else {
			out = append(out, resolve(d, nil, nil))
		}
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, tenantID uuid.UUID, key string) (*Resolved, error) {
	d, ok := defByKey(key)
	if !ok {
		return nil, errs.ErrNotFound.WithDetail("unknown template key")
	}
	row, err := s.q.GetEmailTemplateOverride(ctx, dbgen.GetEmailTemplateOverrideParams{
		TenantID: tenantID, TemplateKey: key,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		r := resolve(d, nil, nil)
		return &r, nil
	}
	if err != nil {
		return nil, err
	}
	r := resolve(d, &row.Subject, &row.Body)
	return &r, nil
}

func (s *Service) Upsert(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, key, subject, body string) (*Resolved, error) {
	d, ok := defByKey(key)
	if !ok {
		return nil, errs.ErrNotFound.WithDetail("unknown template key")
	}
	if strings.TrimSpace(subject) == "" || strings.TrimSpace(body) == "" {
		return nil, errs.ErrUnprocessable.WithDetail("subject and body are required")
	}
	if err := s.q.WithTx(tx).UpsertEmailTemplate(ctx, dbgen.UpsertEmailTemplateParams{
		TenantID: tenantID, TemplateKey: key, Subject: subject, Body: body,
	}); err != nil {
		return nil, err
	}
	r := resolve(d, &subject, &body)
	return &r, nil
}

// Reset removes a tenant override, reverting to the built-in default.
func (s *Service) Reset(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, key string) (*Resolved, error) {
	d, ok := defByKey(key)
	if !ok {
		return nil, errs.ErrNotFound.WithDetail("unknown template key")
	}
	if err := s.q.WithTx(tx).DeleteEmailTemplate(ctx, dbgen.DeleteEmailTemplateParams{
		TenantID: tenantID, TemplateKey: key,
	}); err != nil {
		return nil, err
	}
	r := resolve(d, nil, nil)
	return &r, nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/email-templates", h.list)
	r.Get("/tenants/{tenantID}/email-templates/{key}", h.get)
	r.Put("/tenants/{tenantID}/email-templates/{key}", h.upsert)
	r.Delete("/tenants/{tenantID}/email-templates/{key}", h.reset)
	r.Post("/tenants/{tenantID}/email-templates/{key}/preview", h.preview)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func (h *Handler) audit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID uuid.UUID, action, key string) error {
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		}
	}
	tid := tenantID
	return audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: action, ResourceType: "email_template",
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"template_key": key},
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.Get(r.Context(), tenantID, chi.URLParam(r, "key"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) upsert(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	key := chi.URLParam(r, "key")
	var in struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	res, err := h.Service.Upsert(ctx, tx, tenantID, key, in.Subject, in.Body)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.audit(ctx, tx, r, tenantID, "email_template.updated", key); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	key := chi.URLParam(r, "key")
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	res, err := h.Service.Reset(ctx, tx, tenantID, key)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.audit(ctx, tx, r, tenantID, "email_template.reset", key); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) preview(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.Get(r.Context(), tenantID, chi.URLParam(r, "key"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Vars map[string]string `json:"vars"`
	}
	_ = httpx.DecodeJSON(r, &in)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"subject": Render(res.Subject, in.Vars),
		"body":    Render(res.Body, in.Vars),
	})
}
