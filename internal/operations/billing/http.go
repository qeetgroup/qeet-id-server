package billing

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the billing endpoints.
type Handler struct {
	Service *Service
}

// Mount registers the authenticated billing routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/billing/plans", h.listPlans)
	// A paid plan chosen at signup, before the user has an organization.
	r.Post("/signup/checkout", h.signupCheckout)
	r.Get("/organizations/{organizationID}/billing/subscription", h.getSubscription)
	r.Put("/organizations/{organizationID}/billing/subscription", h.changePlan)
	r.Get("/organizations/{organizationID}/billing/profile", h.getBillingProfile)
	r.Put("/organizations/{organizationID}/billing/profile", h.putBillingProfile)
	r.Post("/organizations/{organizationID}/billing/trial", h.startTrial)
	r.Post("/organizations/{organizationID}/billing/subscription/cancel", h.cancel)
	r.Post("/organizations/{organizationID}/billing/checkout", h.checkout)
	r.Get("/organizations/{organizationID}/billing/invoices", h.listInvoices)
	r.Post("/organizations/{organizationID}/billing/invoices/{invoiceID}/pay", h.payInvoice)
	r.Get("/organizations/{organizationID}/billing/payment-method", h.paymentMethod)
}

// MountPublic registers the payment provider routes. They authenticate by the
// provider's signature rather than a session, so they are public and CSRF-exempt.
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/billing/webhooks/{provider}", h.webhook)
	// The browser posts the signed Razorpay redirect parameters here, because the
	// webhook cannot reach a local server.
	r.Post("/billing/razorpay/verify", h.razorpayVerify)
	// Dev-only sandbox: a mock hosted-checkout page and its pay action, both 404
	// unless the sandbox is enabled.
	r.Get("/billing/sandbox/checkout", h.sandboxCheckoutPage)
	r.Post("/billing/sandbox/pay", h.sandboxPay)
}

// sandboxTmpl renders the dev-only mock hosted-checkout page, labelled as a
// test page, with Pay and Cancel actions.
var sandboxTmpl = template.Must(template.New("sandbox").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sandbox checkout</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0b0c;color:#e5e5e5;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}
.card{background:#161618;border:1px solid #2a2a2e;border-radius:14px;padding:32px;width:360px;box-shadow:0 12px 40px rgba(0,0,0,.4)}
.tag{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#f26d0e;border:1px solid #f26d0e55;border-radius:999px;padding:3px 10px;margin-bottom:18px}
h1{font-size:16px;margin:0 0 4px}.muted{color:#8a8a90;font-size:13px;margin:0 0 20px}
.amount{font-size:34px;font-weight:700;letter-spacing:-.02em;margin:0 0 24px}
button{width:100%;border:0;border-radius:10px;padding:12px;font-size:14px;font-weight:600;cursor:pointer}
.pay{background:#f26d0e;color:#fff;margin-bottom:10px}.cancel{background:transparent;color:#8a8a90;border:1px solid #2a2a2e}
.note{font-size:11px;color:#66666c;margin-top:18px;text-align:center}
</style></head>
<body><div class="card">
<span class="tag">Sandbox · test mode</span>
<h1>{{.Plan}}</h1>
<p class="muted">No real payment is taken.</p>
<p class="amount">{{.Currency}} {{.Amount}}</p>
<form method="POST" action="/v1/billing/sandbox/pay">
  <input type="hidden" name="ref" value="{{.Ref}}">
  <input type="hidden" name="success_url" value="{{.SuccessURL}}">
  <button class="pay" type="submit">Pay {{.Currency}} {{.Amount}}</button>
</form>
<a href="{{.CancelURL}}"><button class="cancel" type="button">Cancel</button></a>
<p class="note">Simulated Stripe/Razorpay hosted checkout for local development.</p>
</div></body></html>`))

type sandboxPageData struct {
	Ref, Plan, Amount, Currency, SuccessURL, CancelURL string
}

// sandboxCheckoutPage renders the mock hosted-checkout page, validating the
// return URLs. It is a 404 when the sandbox is disabled.
func (h *Handler) sandboxCheckoutPage(w http.ResponseWriter, r *http.Request) {
	if !h.Service.SandboxEnabled() {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	q := r.URL.Query()
	successURL, cancelURL := q.Get("success_url"), q.Get("cancel_url")
	if !validReturnURL(successURL) || !validReturnURL(cancelURL) {
		httpx.WriteError(w, r, ErrReturnURLInvalid)
		return
	}
	amt, _ := strconv.ParseInt(q.Get("amount"), 10, 64)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = sandboxTmpl.Execute(w, sandboxPageData{
		Ref:        q.Get("ref"),
		Plan:       q.Get("plan"),
		Amount:     fmt.Sprintf("%.2f", float64(amt)/100),
		Currency:   q.Get("currency"),
		SuccessURL: successURL,
		CancelURL:  cancelURL,
	})
}

// sandboxPay completes the checkout, as a real webhook would, and redirects to
// the success URL. It is a 404 when the sandbox is disabled.
func (h *Handler) sandboxPay(w http.ResponseWriter, r *http.Request) {
	if !h.Service.SandboxEnabled() {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	successURL := r.PostForm.Get("success_url")
	if !validReturnURL(successURL) {
		httpx.WriteError(w, r, ErrReturnURLInvalid)
		return
	}
	if err := h.Service.CompleteCheckout(r.Context(), r.PostForm.Get("ref"), SandboxCard()); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, successURL, http.StatusSeeOther) // #nosec G710 -- dev-only sandbox, refused outside dev by config
}

func (h *Handler) listPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := h.Service.ListPlans(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.Page(plans, ""))
}

func (h *Handler) getSubscription(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.GetSubscription(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

func (h *Handler) startTrial(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		PlanCode string `json:"plan_code"`
		Currency string `json:"currency"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.StartTrial(r.Context(), organizationID, in.PlanCode, in.Currency)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

func (h *Handler) getBillingProfile(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.GetBillingProfile(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) putBillingProfile(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in BillingProfile
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.UpsertBillingProfile(r.Context(), organizationID, in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.GetBillingProfile(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) changePlan(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		PlanCode string `json:"plan_code"`
		Currency string `json:"currency"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.SwitchPlan(r.Context(), organizationID, in.PlanCode, in.Currency, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

// checkout starts a plan change and returns either a hosted-payment URL or
// {status: "active"} when the plan was activated directly.
func (h *Handler) checkout(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		PlanCode   string `json:"plan_code"`
		Currency   string `json:"currency"`
		Country    string `json:"country"`
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !validReturnURL(in.SuccessURL) || !validReturnURL(in.CancelURL) {
		httpx.WriteError(w, r, ErrCheckoutURLInvalid)
		return
	}
	res, err := h.Service.Checkout(r.Context(), organizationID, in.PlanCode, in.Currency, in.Country, in.SuccessURL, in.CancelURL)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// signupCheckout starts a paid checkout for a plan chosen at signup, before the
// user has an organization, which is created only once the payment completes.
func (h *Handler) signupCheckout(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in struct {
		OrgName    string `json:"org_name"`
		OrgSlug    string `json:"org_slug"`
		Region     string `json:"region"`
		PlanCode   string `json:"plan_code"`
		Currency   string `json:"currency"`
		Country    string `json:"country"`
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if strings.TrimSpace(in.OrgName) == "" || strings.TrimSpace(in.OrgSlug) == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	if !validReturnURL(in.SuccessURL) || !validReturnURL(in.CancelURL) {
		httpx.WriteError(w, r, ErrCheckoutURLInvalid)
		return
	}
	res, err := h.Service.StartSignupCheckout(r.Context(), *p.UserID, SignupCheckoutInput{
		OrgName:    strings.TrimSpace(in.OrgName),
		OrgSlug:    strings.TrimSpace(in.OrgSlug),
		Region:     in.Region,
		PlanCode:   in.PlanCode,
		Currency:   in.Currency,
		Country:    in.Country,
		SuccessURL: in.SuccessURL,
		CancelURL:  in.CancelURL,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// validReturnURL reports whether s is an absolute http or https URL with a host,
// as the success and cancel URLs given to a provider must be.
func validReturnURL(s string) bool {
	if s == "" {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// webhook receives a provider's payment webhook and completes the checkout of a
// verified successful payment. A no-op still returns 200, so the provider stops
// retrying.
func (h *Handler) webhook(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	sigHeader := h.Service.WebhookSignatureHeader(provider)
	if sigHeader == "" {
		httpx.WriteError(w, r, ErrProviderUnknown)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	if err := h.Service.HandleWebhook(r.Context(), provider, body, r.Header.Get(sigHeader)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// razorpayVerify completes a checkout from a Razorpay payment-link redirect,
// authenticated by the Razorpay signature. It is idempotent with the webhook.
func (h *Handler) razorpayVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PaymentID     string `json:"razorpay_payment_id"`
		PaymentLinkID string `json:"razorpay_payment_link_id"`
		ReferenceID   string `json:"razorpay_payment_link_reference_id"`
		Status        string `json:"razorpay_payment_link_status"`
		Signature     string `json:"razorpay_signature"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	err := h.Service.CompleteRazorpayCallback(r.Context(), map[string]string{
		"razorpay_payment_id":                in.PaymentID,
		"razorpay_payment_link_id":           in.PaymentLinkID,
		"razorpay_payment_link_reference_id": in.ReferenceID,
		"razorpay_payment_link_status":       in.Status,
		"razorpay_signature":                 in.Signature,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.CancelAtPeriodEnd(r.Context(), organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cancel_at_period_end": true})
}

func (h *Handler) listInvoices(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListInvoices(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// payInvoice opens a hosted checkout for an open invoice, such as a renewal.
func (h *Handler) payInvoice(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	invoiceID, err := httpx.PathUUID(r, "invoiceID", ErrInvoiceNotFound)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !validReturnURL(in.SuccessURL) || !validReturnURL(in.CancelURL) {
		httpx.WriteError(w, r, ErrCheckoutURLInvalid)
		return
	}
	res, err := h.Service.PayInvoice(r.Context(), organizationID, invoiceID, in.SuccessURL, in.CancelURL)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// paymentMethod returns what the organization last paid with, or null.
func (h *Handler) paymentMethod(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	m, err := h.Service.LastPaymentMethod(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"payment_method": m})
}
