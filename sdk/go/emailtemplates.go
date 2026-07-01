package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type EmailTemplate struct {
	TenantID    string `json:"tenant_id"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
	HTMLBody    string `json:"html_body"`
	TextBody    string `json:"text_body,omitempty"`
	FromName    string `json:"from_name,omitempty"`
	FromAddress string `json:"from_address,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type UpdateEmailTemplateInput struct {
	Subject     *string `json:"subject,omitempty"`
	HTMLBody    *string `json:"html_body,omitempty"`
	TextBody    *string `json:"text_body,omitempty"`
	FromName    *string `json:"from_name,omitempty"`
	FromAddress *string `json:"from_address,omitempty"`
}

type EmailPreviewResult struct {
	Sent bool `json:"sent"`
}

type EmailTemplates struct{ http *httpClient }

func (r *EmailTemplates) Get(ctx context.Context, tenantID, templateType string) (*EmailTemplate, error) {
	var out EmailTemplate
	err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/email-templates/"+url.PathEscape(templateType), nil, nil, &out, true)
	return &out, err
}

func (r *EmailTemplates) Update(ctx context.Context, tenantID, templateType string, in UpdateEmailTemplateInput) (*EmailTemplate, error) {
	var out EmailTemplate
	err := r.http.do(ctx, http.MethodPut, "/v1/tenants/"+url.PathEscape(tenantID)+"/email-templates/"+url.PathEscape(templateType), nil, in, &out, false)
	return &out, err
}

func (r *EmailTemplates) Preview(ctx context.Context, tenantID, templateType, to string) (*EmailPreviewResult, error) {
	var out EmailPreviewResult
	body := map[string]string{"to": to}
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/email-templates/"+url.PathEscape(templateType)+"/preview", nil, body, &out, false)
	return &out, err
}
