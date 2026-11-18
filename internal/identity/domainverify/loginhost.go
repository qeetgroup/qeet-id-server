package domainverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// loginHostSuffix is the zone organizations point their CNAME at. Kept here rather
// than in config because it is part of the published DNS instructions: changing
// it invalidates every record an operator has already created.
const loginHostSuffix = "organizations.id.qeet.in"

// loginVerifyHost is the TXT record proving control of the login hostname. It's
// separate from the email-domain check (_qeet-verification) because the two
// prove different things and can be at different stages.
const loginVerifyHost = "_qeetid-verify"

// LoginDomainStatus is the provisioning state of an organization's custom hosted-login
// hostname. Status is not_configured, pending or active; TLSState is
// not_started, pending or issued; EndpointState is not_available or live.
type LoginDomainStatus struct {
	LoginDomain string `json:"login_domain"`
	Status      string `json:"status"`
	// CheckedAt is when this result was found; nil with no address set.
	CheckedAt *time.Time `json:"checked_at"`

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

// shortOrganization is the stable per-organization label used in the CNAME target, so the
// instruction is deterministic for a given organization rather than regenerated.
func shortOrganization(organizationID uuid.UUID) string {
	return strings.Split(organizationID.String(), "-")[0]
}

func loginRecords(organizationID uuid.UUID, host string) []DNSRecord {
	return []DNSRecord{
		{Type: "CNAME", Name: host, Value: fmt.Sprintf("%s.%s", shortOrganization(organizationID), loginHostSuffix)},
		{
			Type:  "TXT",
			Name:  loginVerifyHost + "." + host, // where LoginDomain looks it up
			Value: fmt.Sprintf("qeetid-verify=%s", shortOrganization(organizationID)),
		},
	}
}

// The hosted login's health route and the service it names, which answer on
// every hostname the hosted login serves.
const (
	hostedLoginHealth  = "/healthz"
	hostedLoginService = "qeet-id-hosted"
)

// loginProbeTimeout bounds each live check of a custom login hostname.
const loginProbeTimeout = 5 * time.Second

// loginProbeClient returns the client that checks a custom login hostname over
// HTTPS: only to destinations policy allows, and without following redirects,
// so the answer is the hostname's own.
func loginProbeClient(policy *egress.Policy) *http.Client {
	c := policy.HTTPClient(loginProbeTimeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// LoginDomain reports the provisioning state of the organization's custom login
// hostname as last checked, checking it now only when it never was or the
// hostname has changed since.
func (s *Service) LoginDomain(ctx context.Context, organizationID uuid.UUID) (*LoginDomainStatus, error) {
	host := s.loginHost(ctx, organizationID)
	if host == "" {
		return s.loginDomainStatus(ctx, organizationID, host), nil
	}
	last, err := s.q.GetLoginDomainCheck(ctx, organizationID)
	if err == nil && last.Host == host {
		var st LoginDomainStatus
		if json.Unmarshal(last.Result, &st) == nil {
			at := last.CheckedAt
			st.CheckedAt = &at
			return &st, nil
		}
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return s.CheckLoginDomain(ctx, organizationID)
}

// CheckLoginDomain checks each stage of the organization's custom login hostname now
// and keeps the result for LoginDomain.
func (s *Service) CheckLoginDomain(ctx context.Context, organizationID uuid.UUID) (*LoginDomainStatus, error) {
	host := s.loginHost(ctx, organizationID)
	st := s.loginDomainStatus(ctx, organizationID, host)
	if host == "" {
		return st, nil
	}
	// Postgres keeps microseconds: truncated, the time answered now is the one a
	// later read returns, on any clock.
	now := time.Now().UTC().Truncate(time.Microsecond)
	st.CheckedAt = &now
	result, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	if err := s.q.SaveLoginDomainCheck(ctx, dbgen.SaveLoginDomainCheckParams{OrganizationID: organizationID, Host: host, CheckedAt: now, Result: result}); err != nil {
		return nil, err
	}
	return st, nil
}

// loginHost is the organization's custom login hostname, normalised; "" for none.
func (s *Service) loginHost(ctx context.Context, organizationID uuid.UUID) string {
	host, err := s.q.LoginHost(ctx, organizationID)
	if err != nil {
		// No branding row yet simply means no custom domain has been set.
		host = ""
	}
	return strings.TrimSpace(strings.ToLower(host))
}

// loginDomainStatus checks host's stages in order: its DNS records, then a
// certificate valid for it, then the hosted login answering on it. The TLS
// certificate is issued at the deployment edge, so it is observed, not
// assumed. Status is active once all three are done.
func (s *Service) loginDomainStatus(ctx context.Context, organizationID uuid.UUID, host string) *LoginDomainStatus {
	st := &LoginDomainStatus{
		LoginDomain: host, Status: "not_configured",
		TLSState: "not_started", TLSDetail: "Issued automatically after DNS is verified.",
		EndpointState: "not_available",
	}
	if host == "" {
		st.DNSDetail = "No custom login domain configured."
		return st
	}
	st.Records = loginRecords(organizationID, host)
	st.Status = "pending"
	if !validDomain(host) {
		st.DNSDetail = "The login domain isn't a valid hostname."
		return st
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	st.DNSCheckedAt = &now
	want := fmt.Sprintf("qeetid-verify=%s", shortOrganization(organizationID))
	records, _ := s.resolver.LookupTXT(lookupCtx, loginVerifyHost+"."+host)
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			st.DNSVerified = true
			break
		}
	}
	if !st.DNSVerified {
		st.DNSDetail = "We're checking for your DNS records."
		return st
	}
	st.DNSDetail = "DNS records found."

	tlsIssued, live := s.probeLoginHost(ctx, host)
	if !tlsIssued {
		st.TLSState, st.TLSDetail = "pending", "Certificate issuance in progress."
		return st
	}
	st.TLSState, st.TLSDetail = "issued", "Certificate issued."
	if live {
		st.EndpointState, st.EndpointURL = "live", "https://"+host
		st.Status = "active"
	}
	return st
}

// probeLoginHost asks host for the hosted login's health over HTTPS. tlsIssued
// reports that host served a certificate valid for it; live, that the hosted
// login answered.
func (s *Service) probeLoginHost(ctx context.Context, host string) (tlsIssued, live bool) {
	if s.web == nil {
		return false, false
	}
	ctx, cancel := context.WithTimeout(ctx, loginProbeTimeout)
	defer cancel()
	target := url.URL{Scheme: "https", Host: host, Path: hostedLoginHealth}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false, false
	}
	resp, err := s.web.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	var health struct {
		Status  string `json:"status"`
		Service string `json:"service"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&health)
	return true, err == nil && resp.StatusCode == http.StatusOK &&
		health.Status == "ok" && health.Service == hostedLoginService
}

func (h *Handler) loginDomain(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.LoginDomain(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// checkLoginDomain serves POST /organizations/{organizationID}/login-domain/check: a new
// check of the sign-in address, kept as its last.
func (h *Handler) checkLoginDomain(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.CheckLoginDomain(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}
