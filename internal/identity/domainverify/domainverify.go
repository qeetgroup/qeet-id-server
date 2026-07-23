// Package domainverify lets a tenant claim and prove ownership of an email domain
// (B2B SSO onboarding) via a DNS TXT record, checked only on an explicit admin
// action. A verified domain can later gate org SSO / JIT provisioning.
package domainverify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// dnsHostPrefix is the subdomain the TXT record lives under, so verification
// never clobbers a tenant's apex TXT records (SPF, etc.).
const dnsHostPrefix = "_qeet-verification."

type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	resolver interface {
		LookupTXT(ctx context.Context, name string) ([]string, error)
	}
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), resolver: net.DefaultResolver}
}

type Domain struct {
	ID                uuid.UUID  `json:"id"`
	Domain            string     `json:"domain"`
	VerificationToken string     `json:"verification_token"`
	DNSRecordName     string     `json:"dns_record_name"`
	DNSRecordType     string     `json:"dns_record_type"`
	DNSRecordValue    string     `json:"dns_record_value"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

func (d *Domain) fillDNS() {
	d.DNSRecordName = dnsHostPrefix + d.Domain
	d.DNSRecordType = "TXT"
	d.DNSRecordValue = d.VerificationToken
}

// normalizeDomain lowercases, trims, and strips any scheme/path/port a user may
// have pasted, leaving a bare hostname.
func normalizeDomain(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if i := strings.IndexAny(d, "/:"); i >= 0 {
		d = d[:i]
	}
	return strings.TrimSuffix(d, ".")
}

func validDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, r := range d {
		if !(r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "qeet-verify-" + hex.EncodeToString(b), nil
}

// pgtypeToTimePtr converts a pgtype.Timestamptz returned by generated code to *time.Time.
func pgtypeToTimePtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

// rowToDomain maps the common columns (id, domain, verification_token,
// verified_at, created_at) to the domain Domain struct. This signature matches
// the InsertDomainRow, GetDomainForVerifyRow, ListDomainsRow, and MarkDomainVerifiedRow
// generated types, which all have identical fields.
func rowToDomain(id uuid.UUID, domain, token string, verifiedAt pgtype.Timestamptz, createdAt time.Time) Domain {
	d := Domain{
		ID:                id,
		Domain:            domain,
		VerificationToken: token,
		VerifiedAt:        pgtypeToTimePtr(verifiedAt),
		CreatedAt:         createdAt,
	}
	d.fillDNS()
	return d
}

// Add registers a domain for a tenant and returns the DNS record to publish.
func (s *Service) Add(ctx context.Context, tenantID uuid.UUID, raw string) (*Domain, error) {
	domain := normalizeDomain(raw)
	if !validDomain(domain) {
		return nil, errs.ErrUnprocessable.WithMessage("Enter a valid domain, e.g. acme.com.")
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	row, err := s.q.InsertDomain(ctx, dbgen.InsertDomainParams{
		TenantID:          tenantID,
		Domain:            domain,
		VerificationToken: token,
	})
	if err != nil {
		if strings.Contains(err.Error(), "uq_tenant_domain") {
			return nil, errs.ErrConflict.WithDetail("domain already added")
		}
		return nil, err
	}
	d := rowToDomain(row.ID, row.Domain, row.VerificationToken, row.VerifiedAt, row.CreatedAt)
	return &d, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Domain, error) {
	rows, err := s.q.ListDomains(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Domain, 0, len(rows))
	for _, row := range rows {
		d := rowToDomain(row.ID, row.Domain, row.VerificationToken, row.VerifiedAt, row.CreatedAt)
		out = append(out, d)
	}
	return out, nil
}

// Verify looks up the DNS TXT record and, if the token is present, marks the
// domain verified. A missing record returns a friendly 422 (DNS may still be
// propagating); an already-verified-by-another-tenant collision returns 409.
func (s *Service) Verify(ctx context.Context, id, tenantID uuid.UUID) (*Domain, error) {
	row, err := s.q.GetDomainForVerify(ctx, dbgen.GetDomainForVerifyParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := rowToDomain(row.ID, row.Domain, row.VerificationToken, row.VerifiedAt, row.CreatedAt)
	if d.VerifiedAt != nil {
		return &d, nil // already verified — idempotent
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	records, lerr := s.resolver.LookupTXT(lookupCtx, dnsHostPrefix+d.Domain)
	found := false
	for _, rec := range records {
		if strings.TrimSpace(rec) == d.VerificationToken {
			found = true
			break
		}
	}
	if lerr != nil || !found {
		return nil, errs.ErrUnprocessable.WithMessage(
			"We couldn't find the verification record yet. DNS changes can take a few minutes to propagate — add the TXT record and try again.")
	}

	updated, err := s.q.MarkDomainVerified(ctx, dbgen.MarkDomainVerifiedParams{ID: id, TenantID: tenantID})
	if err != nil {
		if strings.Contains(err.Error(), "uq_verified_domain") {
			return nil, errs.ErrConflict.WithMessage("This domain is already verified by another organization.")
		}
		return nil, err
	}
	verified := rowToDomain(updated.ID, updated.Domain, updated.VerificationToken, updated.VerifiedAt, updated.CreatedAt)
	return &verified, nil
}

func (s *Service) Remove(ctx context.Context, id, tenantID uuid.UUID) error {
	n, err := s.q.DeleteDomain(ctx, dbgen.DeleteDomainParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/domains", h.list)
	r.Post("/tenants/{tenantID}/domains", h.add)
	r.Post("/tenants/{tenantID}/domains/{id}/verify", h.verify)
	r.Delete("/tenants/{tenantID}/domains/{id}", h.remove)
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

type addInput struct {
	Domain string `json:"domain"`
}

func (h *Handler) add(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in addInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.Service.Add(r.Context(), tenantID, in.Domain)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, d)
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	d, err := h.Service.Verify(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Remove(r.Context(), id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
