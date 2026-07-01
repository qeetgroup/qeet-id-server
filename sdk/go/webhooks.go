package qeetid

import (
	"context"
	"net/http"
	"net/url"
)

type Webhook struct {
	ID        string   `json:"id"`
	TenantID  string   `json:"tenant_id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Enabled   bool     `json:"enabled"`
	Secret    string   `json:"secret,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

type CreateWebhookInput struct {
	URL     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled *bool    `json:"enabled,omitempty"`
}

type UpdateWebhookInput struct {
	URL     *string  `json:"url,omitempty"`
	Events  []string `json:"events,omitempty"`
	Enabled *bool    `json:"enabled,omitempty"`
}

type WebhookDelivery struct {
	ID             string `json:"id"`
	WebhookID      string `json:"webhook_id"`
	Event          string `json:"event"`
	Status         string `json:"status"`
	ResponseStatus int    `json:"response_status,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type Webhooks struct{ http *httpClient }

func (r *Webhooks) Create(ctx context.Context, tenantID string, in CreateWebhookInput) (*Webhook, error) {
	var out Webhook
	err := r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/webhooks", nil, in, &out, false)
	return &out, err
}

func (r *Webhooks) Get(ctx context.Context, tenantID, id string) (*Webhook, error) {
	var out Webhook
	err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/webhooks/"+url.PathEscape(id), nil, nil, &out, true)
	return &out, err
}

func (r *Webhooks) Update(ctx context.Context, tenantID, id string, in UpdateWebhookInput) (*Webhook, error) {
	var out Webhook
	err := r.http.do(ctx, http.MethodPatch, "/v1/tenants/"+url.PathEscape(tenantID)+"/webhooks/"+url.PathEscape(id), nil, in, &out, false)
	return &out, err
}

func (r *Webhooks) Delete(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(tenantID)+"/webhooks/"+url.PathEscape(id), nil, nil, nil, true)
}

func (r *Webhooks) Test(ctx context.Context, tenantID, id string) error {
	return r.http.do(ctx, http.MethodPost, "/v1/tenants/"+url.PathEscape(tenantID)+"/webhooks/"+url.PathEscape(id)+"/test", nil, struct{}{}, nil, false)
}

func (r *Webhooks) List(ctx context.Context, tenantID string) ([]Webhook, error) {
	var env struct {
		Items []Webhook `json:"items"`
		Data  []Webhook `json:"data"`
	}
	if err := r.http.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(tenantID)+"/webhooks", nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}

func (r *Webhooks) ListDeliveries(ctx context.Context, tenantID, webhookID string) ([]WebhookDelivery, error) {
	var env struct {
		Items []WebhookDelivery `json:"items"`
		Data  []WebhookDelivery `json:"data"`
	}
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/webhooks/" + url.PathEscape(webhookID) + "/deliveries"
	if err := r.http.do(ctx, http.MethodGet, path, nil, nil, &env, true); err != nil {
		return nil, err
	}
	if env.Items != nil {
		return env.Items, nil
	}
	return env.Data, nil
}

func (r *Webhooks) RetryDelivery(ctx context.Context, tenantID, webhookID, deliveryID string) error {
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/webhooks/" + url.PathEscape(webhookID) + "/deliveries/" + url.PathEscape(deliveryID) + "/retry"
	return r.http.do(ctx, http.MethodPost, path, nil, struct{}{}, nil, false)
}
