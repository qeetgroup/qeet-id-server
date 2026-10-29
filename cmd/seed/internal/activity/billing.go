package activity

import (
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
)

// sellerState is Qeet Group's registered state, for GST: a buyer in the same
// state pays CGST and SGST, any other Indian buyer IGST, and a buyer abroad
// nothing (an export).
const sellerState = "Karnataka"

// profileSpec is an organisation's billing details.
type profileSpec struct {
	legal, email, line1, line2, city, state, postal string
	taxType, pan                                    string // pan: the PAN inside an Indian GSTIN; or the VAT number
}

// profiles are the billing details of the organisations that pay. GSTINs are
// fictional but well formed, check character included.
var profiles = map[string]profileSpec{
	"qeet":      {"Qeet Group Private Limited", "accounts@qeet.in", "4th Floor, Prestige Atlanta, 80 Feet Road", "Koramangala 1A Block", "Bengaluru", "Karnataka", "560034", "gstin", "AAKCQ4187M"},
	"northwind": {"Northwind Capital Finance Limited", "accounts.payable@northwindcapital.in", "Level 12, One BKC, G Block", "Bandra Kurla Complex, Bandra (East)", "Mumbai", "Maharashtra", "400051", "gstin", "AAFCN8312K"},
	"meridian":  {"Meridian Health System, Inc.", "ap@meridianhealth.us", "800 Boylston Street, Suite 1400", "", "Boston", "Massachusetts", "02199", "none", ""},
	"lumen":     {"Lumen Labs GmbH", "billing@lumenlabshq.dev", "Torstraße 140", "", "Berlin", "Berlin", "10119", "vat", "DE318472951"},
	"aster":     {"Aster Retail Private Limited", "finance@asterretail.in", "No. 42, 2nd Floor, 100 Feet Road", "HAL 2nd Stage, Indiranagar", "Bengaluru", "Karnataka", "560038", "gstin", "AAJCA5521Q"},
	"vertex":    {"Vertex Freight Co. LLC", "ap@vertexfreightco.us", "222 W Adams Street, Suite 900", "", "Chicago", "Illinois", "60606", "none", ""},
	"kestrel":   {"Kestrel Insurance Brokers Private Limited", "accounts@kestrelinsurance.in", "Office 503, Panchshil Tech Park", "Yerwada", "Pune", "Maharashtra", "411006", "gstin", "AAHCK7745P"},
	"cobalt":    {"Cobalt Creative Ltd", "accounts@cobaltcreative.co.uk", "Unit 4, 23 Charlotte Road", "Shoreditch", "London", "Greater London", "EC2A 3PB", "vat", "GB284661293"},
}

// gstStateCodes are the GST state codes a GSTIN starts with.
var gstStateCodes = map[string]string{"Karnataka": "29", "Maharashtra": "27"}

// gstin is a well-formed GSTIN for pan registered in state: state code, PAN,
// entity number, "Z" and the check character.
func gstin(state, pan string) string {
	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	body := gstStateCodes[state] + pan + "1Z"
	sum := 0
	for i, c := range body {
		v := strings.IndexRune(chars, c) * (i%2 + 1)
		sum += v/36 + v%36
	}
	return body + string(chars[(36-sum%36)%36])
}

// billingHistory gives every organisation the billing its plan and story
// call for, through the billing service: a billing profile, a GST invoice
// for every month since it subscribed (one voided and reissued at the two
// largest), and the subscription's state today — a trial that ends nine
// days after it began, a payment that failed this month, or a cancelled plan
// that lapsed back to Free.
func (h *history) billingHistory() {
	w := h.w
	svc := w.Deps.Billing.Service
	svc.SetTaxConfig(billing.TaxConfig{Enabled: true, SellerCountry: "IN", SellerState: sellerState, GSTRateBps: 1800})
	defer svc.SetTaxConfig(billing.TaxConfig{Enabled: w.Cfg.BillingTaxEnabled, SellerCountry: w.Cfg.BillingSellerCountry,
		SellerState: w.Cfg.BillingSellerState, GSTRateBps: w.Cfg.BillingGSTRateBps})

	for _, o := range w.Orgs {
		s := o.Spec
		if spec, ok := profiles[s.Slug]; ok {
			taxID := spec.pan
			if spec.taxType == "gstin" {
				taxID = gstin(spec.state, spec.pan)
			}
			w.At(s.Since.Add(10*time.Minute), func() {
				w.Check(svc.UpsertBillingProfile(w.Ctx, o.ID, billing.BillingProfile{
					LegalName: spec.legal, BillingEmail: spec.email, AddressLine1: spec.line1, AddressLine2: spec.line2,
					City: spec.city, State: spec.state, PostalCode: spec.postal, Country: s.Country, TaxIDType: spec.taxType, TaxID: taxID,
				}), "billing profile of "+s.Slug)
			})
		}
		switch {
		case s.Billing == "trialing":
			// The trial runs fourteen days from the day it started.
			end := s.Since.Add(20*time.Minute + 14*24*time.Hour)
			w.Exec("trial of "+s.Slug, `UPDATE tenant.subscriptions SET trial_end = $2, current_period_end = $2 WHERE tenant_id = $1`, o.ID, end)
			continue
		case s.Plan == "free":
			fixPeriods(w, o, s.Since.Add(20*time.Minute))
			continue
		}
		h.invoices(o)
	}
	numberInvoices(w)
}

// numberInvoices numbers every invoice that charges something in its GST
// series, by the Indian financial year it was issued in: the history was
// issued today and dated back afterwards, and the census's first invoices were
// reissued, so the numbers the service gave run out of order.
func numberInvoices(w *world.World) {
	w.Exec("clear invoice numbers", `UPDATE tenant.invoices SET invoice_number = NULL WHERE invoice_number IS NOT NULL`)
	w.Exec("number invoices", `
		WITH dated AS (
			SELECT id, issued_at,
			       date_trunc('year', (issued_at AT TIME ZONE 'Asia/Kolkata') - interval '3 months') AS fy_start
			FROM tenant.invoices WHERE amount_minor > 0
		), numbered AS (
			SELECT id, to_char(fy_start, 'YYYY') || '-' || to_char(fy_start + interval '1 year', 'YY') AS fy,
			       row_number() OVER (PARTITION BY fy_start ORDER BY issued_at, id) AS n
			FROM dated
		)
		UPDATE tenant.invoices i SET invoice_number = numbered.fy || '/' || lpad(numbered.n::text, 6, '0')
		FROM numbered WHERE i.id = numbered.id`)
	w.Exec("reset invoice series", `DELETE FROM platform.invoice_number_series`)
	w.Exec("invoice series", `
		INSERT INTO platform.invoice_number_series (financial_year, last_number)
		SELECT split_part(invoice_number, '/', 1), max(split_part(invoice_number, '/', 2)::bigint)
		FROM tenant.invoices WHERE invoice_number IS NOT NULL
		GROUP BY 1`)
}

// invoices issues o's monthly invoices from the day it subscribed, each
// through ChangePlan at the start of its period, and sets the subscription's
// state today.
func (h *history) invoices(o *world.Org) {
	w := h.w
	s := o.Spec
	svc := w.Deps.Billing.Service
	owner := o.Owner
	start := s.Since.Add(20 * time.Minute)
	// The census subscribed without tax details; its invoice is issued again here.
	w.Exec("census invoice of "+s.Slug, `DELETE FROM tenant.invoices WHERE tenant_id = $1`, o.ID)
	cancelled := time.Time{}
	if s.Billing == "canceled" {
		// Cancelled about five months in, effective at the end of the period.
		cancelled = start.AddDate(0, 5, 0)
	}
	last := start
	for k := 0; ; k++ {
		at := start.AddDate(0, k, 0)
		if at.After(w.Now) || (!cancelled.IsZero() && !at.Before(cancelled)) {
			break
		}
		last = at
		w.At(at, func() {
			w.Tx("invoice "+s.Slug, func(tx pgx.Tx) error {
				_, err := svc.ChangePlan(w.Ctx, tx, o.ID, s.Plan, s.Currency)
				return err
			})
		})
	}
	// ChangePlan dates a period's end a month from the real now, and takes no
	// payment, so it leaves each invoice open: these were paid. The
	// subscription's current period is its latest invoice's.
	w.Exec("invoice periods of "+s.Slug, `UPDATE tenant.invoices SET period_end = period_start + interval '1 month', status = 'paid' WHERE tenant_id = $1`, o.ID)
	w.Exec("period of "+s.Slug, `
		UPDATE tenant.subscriptions s SET current_period_start = i.period_start, current_period_end = i.period_end
		FROM (SELECT period_start, period_end FROM tenant.invoices WHERE tenant_id = $1 ORDER BY period_start DESC LIMIT 1) i
		WHERE s.tenant_id = $1`, o.ID)

	// Who subscribed, and how they paid: a card checkout for the self-serve
	// plans, an Enterprise contract invoiced directly.
	ip := officeIP(owner)
	price := planPrice(w, s.Plan, s.Currency)
	w.Audit(start, audit.Event{TenantID: &o.ID, ActorUserID: &owner.ID, Action: "billing.plan_changed", ResourceType: "subscription",
		IP: ip, UserAgent: owner.Device.UserAgent, RequestID: h.requestID(),
		Metadata: map[string]any{"plan": s.Plan, "currency": s.Currency, "amount_minor": price}})
	if s.Plan != "enterprise" {
		provider, ref := "stripe", "cs_live_a1"+token(w, 56)
		if s.Currency == "INR" {
			provider, ref = "razorpay", "order_"+token(w, 14)
		}
		// The checkout charged what its first invoice shows, tax included.
		w.Exec("checkout of "+s.Slug, `
			INSERT INTO tenant.billing_checkouts (tenant_id, provider, provider_ref, plan_code, currency, amount_minor,
			    taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply, status, created_at, completed_at)
			SELECT $1::uuid, $2::text, $3::text, $4::text, $5::text, i.amount_minor, i.taxable_amount_minor, i.tax_amount_minor, i.tax_rate_bps, i.tax_type,
			       i.place_of_supply, 'completed', $6, $6::timestamptz + interval '3 minutes'
			FROM tenant.invoices i WHERE i.tenant_id = $1
			ORDER BY i.period_start LIMIT 1`,
			o.ID, provider, ref, s.Plan, s.Currency, start.Add(-5*time.Minute))
	}

	switch s.Billing {
	case "past_due":
		// This month's renewal was declined; a retry with another card failed too.
		w.Exec("unpaid invoice of "+s.Slug, `
			UPDATE tenant.invoices SET status = 'open'
			WHERE tenant_id = $1 AND id = (SELECT id FROM tenant.invoices WHERE tenant_id = $1 ORDER BY period_start DESC LIMIT 1)`, o.ID)
		w.Exec("past due "+s.Slug, `UPDATE tenant.subscriptions SET status = 'past_due', updated_at = $2 WHERE tenant_id = $1`,
			o.ID, last.Add(26*time.Hour))
		w.Exec("failed checkout of "+s.Slug, `
			INSERT INTO tenant.billing_checkouts (tenant_id, provider, provider_ref, plan_code, currency, amount_minor,
			    taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply, status, created_at)
			SELECT $1::uuid, 'razorpay', $2::text, $3::text, $4::text, i.amount_minor, i.taxable_amount_minor, i.tax_amount_minor, i.tax_rate_bps,
			       i.tax_type, i.place_of_supply, 'failed', $5::timestamptz
			FROM tenant.invoices i WHERE i.tenant_id = $1
			ORDER BY i.period_start DESC LIMIT 1`,
			o.ID, "order_"+token(w, 14), s.Plan, s.Currency, w.WorkHours(last.Add(5*24*time.Hour), o.Loc))
	case "canceled":
		at := w.WorkHours(last.Add(13*24*time.Hour), o.Loc)
		w.Audit(at, audit.Event{TenantID: &o.ID, ActorUserID: &owner.ID, Action: "billing.subscription_canceled",
			ResourceType: "subscription", IP: ip, UserAgent: owner.Device.UserAgent,
			RequestID: h.requestID()})
		w.Exec("cancelled "+s.Slug, `UPDATE tenant.subscriptions SET status = 'canceled', cancel_at_period_end = false, updated_at = $2
			WHERE tenant_id = $1`, o.ID, last.AddDate(0, 1, 0))
		// The lapsed plan leaves the organisation on Free.
		w.Exec("free again "+s.Slug, `UPDATE tenant.tenants SET plan = 'free', updated_at = $2 WHERE id = $1`, o.ID, last.AddDate(0, 1, 0))
	default:
		if s.Plan == "enterprise" && len(o.People) >= 50 {
			voidDuplicate(w, o, start.AddDate(0, 3, 0))
		}
	}
}

// voidDuplicate adds an invoice issued twice for the period starting at
// start: the first copy was voided an hour later.
func voidDuplicate(w *world.World, o *world.Org, start time.Time) {
	w.Exec("voided invoice of "+o.Spec.Slug, `
		INSERT INTO tenant.invoices (tenant_id, plan_code, currency, amount_minor, status, period_start, period_end, issued_at,
		                             taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply)
		SELECT tenant_id, plan_code, currency, amount_minor, 'void', period_start, period_end, issued_at - interval '70 minutes',
		       taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply
		FROM tenant.invoices WHERE tenant_id = $1 AND period_start BETWEEN $2 AND $2::timestamptz + interval '1 minute'`, o.ID, start)
}

// fixPeriods dates a free subscription's current period, which ChangePlan
// set from the real now, a month at a time from start.
func fixPeriods(w *world.World, o *world.Org, start time.Time) {
	last := start
	for at := start; !at.After(w.Now); at = at.AddDate(0, 1, 0) {
		last = at
	}
	w.Exec("free period of "+o.Spec.Slug, `UPDATE tenant.subscriptions SET current_period_start = $2,
		current_period_end = $2::timestamptz + interval '1 month' WHERE tenant_id = $1`, o.ID, last)
	w.Exec("free invoice of "+o.Spec.Slug, `UPDATE tenant.invoices SET period_end = period_start + interval '1 month' WHERE tenant_id = $1`, o.ID)
}

// planPrice is the plan's monthly price in currency, from the catalogue.
func planPrice(w *world.World, plan, currency string) int64 {
	plans, err := w.Deps.Billing.Service.ListPlans(w.Ctx)
	w.Check(err, "list plans")
	for _, p := range plans {
		if p.Code == plan {
			return p.Prices[currency]
		}
	}
	return 0
}

// token is n random letters and digits, for payment providers' references.
func token(w *world.World, n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[w.Rand.IntN(len(chars))]
	}
	return string(b)
}
