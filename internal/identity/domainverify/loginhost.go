package domainverify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// loginHostSuffix is the zone tenants point their CNAME at. Kept here rather
// than in config because it is part of the published DNS instructions: changing
// it invalidates every record an operator has already created.
const loginHostSuffix = "tenants.id.qeet.in"

// loginVerifyHost is the TXT record proving control of the login hostname. It's
// separate from the email-domain check (_qeet-verification) because the two
// prove different things and can be at different stages.
const loginVerifyHost = "_qeetid-verify"

// LoginDomainStatus is the provisioning state of a tenant's custom hosted-login
// hostname. Status is not_configured, pending or active; TLSState is
// not_started, pending or issued; EndpointState is not_available or live.
type LoginDomainStatus struct {
	LoginDomain string `json:"login_domain"`
	Status      string `json:"status"`

	DNSVerified   bool       `json:"dns_verified"`
	DNSCheckedAt  *time.Time `json:"dns_checked_at,omitempty"`
	DNSDetail     string     `json:"dns_detail"`
	TLSState      string     `json:"tls_state"`
	TLSDetail     string     `json:"tls_detail"`
	EndpointState string     `json:"endpoint_state"`
	EndpointURL   string     `json:"endpoint_url,omitempty"`

	Records []DNSRecord `json:"records"`
}

// DNSRecord is one row of the "Required DNS records" table.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// shortTenant is the stable per-tenant label used in the CNAME target, so the
// instruction is deterministic for a given tenant rather than regenerated.
func shortTenant(tenantID uuid.UUID) string {
	return strings.Split(tenantID.String(), "-")[0]
}

func loginRecords(tenantID uuid.UUID, host string) []DNSRecord {
	return []DNSRecord{
		{Type: "CNAME", Name: host, Value: fmt.Sprintf("%s.%s", shortTenant(tenantID), loginHostSuffix)},
		{
			Type:  "TXT",
			Name:  loginVerifyHost,
			Value: fmt.Sprintf("qeetid-verify=%s", shortTenant(tenantID)),
		},
	}
}

// LoginDomain reports the provisioning state of the tenant's custom login
// hostname. DNS is checked live; TLS and the endpoint are never reported ready,
// because no certificate pipeline confirms them yet.
func (s *Service) LoginDomain(ctx context.Context, tenantID uuid.UUID) (*LoginDomainStatus, error) {
	var host string
	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(custom_domain, '') FROM tenant.branding WHERE tenant_id = $1`,
		tenantID).Scan(&host); err != nil {
		// No branding row yet simply means no custom domain has been set.
		host = ""
	}
	host = strings.TrimSpace(strings.ToLower(host))

	st := &LoginDomainStatus{LoginDomain: host, Status: "not_configured"}
	if host == "" {
		st.DNSDetail = "No custom login domain configured."
		st.TLSState, st.TLSDetail = "not_started", "Issued automatically after DNS is verified."
		st.EndpointState = "not_available"
		return st, nil
	}

	st.Records = loginRecords(tenantID, host)
	st.Status = "pending"

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	st.DNSCheckedAt = &now

	want := fmt.Sprintf("qeetid-verify=%s", shortTenant(tenantID))
	records, err := s.resolver.LookupTXT(lookupCtx, loginVerifyHost+"."+host)
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			st.DNSVerified = true
			break
		}
	}
	switch {
	case st.DNSVerified:
		st.DNSDetail = "DNS records found."
	case err != nil:
		st.DNSDetail = "We're checking for your DNS records."
	default:
		st.DNSDetail = "We're checking for your DNS records."
	}

	if st.DNSVerified {
		// DNS is the only stage we can observe today. Issuance is reported as
		// pending — not issued — until a certificate pipeline exists to confirm it.
		st.TLSState, st.TLSDetail = "pending", "Certificate issuance in progress."
		st.EndpointState = "not_available"
	} else {
		st.TLSState, st.TLSDetail = "not_started", "Issued automatically after DNS is verified."
		st.EndpointState = "not_available"
	}
	return st, nil
}

func (h *Handler) loginDomain(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.LoginDomain(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}
