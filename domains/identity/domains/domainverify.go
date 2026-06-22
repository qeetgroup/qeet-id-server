// Package domainverify lets a tenant claim and prove ownership of an email
// domain (B2B SSO onboarding). Ownership is proven by a DNS TXT record, checked
// on an explicit admin action — no implicit trust. A verified domain can later
// gate org SSO / JIT provisioning (that enforcement is a separate step).
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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

// dnsHostPrefix is the subdomain the TXT record lives under, so verification
// never clobbers a tenant's apex TXT records (SPF, etc.).
const dnsHostPrefix = "_qeet-verification."

type Service struct {
	pool     *pgxpool.Pool
	resolver interface {
		LookupTXT(ctx context.Context, name string) ([]string, error)
	}
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, resolver: net.DefaultResolver}
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
	var d Domain
	err = s.pool.QueryRow(ctx, `
		INSERT INTO tenant.domains (tenant_id, domain, verification_token)
		VALUES ($1, $2, $3)
		RETURNING id, domain, verification_token, verified_at, created_at
	`, tenantID, domain, token).Scan(&d.ID, &d.Domain, &d.VerificationToken, &d.VerifiedAt, &d.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "uq_tenant_domain") {
			return nil, errs.ErrConflict.WithDetail("domain already added")
		}
		return nil, err
	}
	d.fillDNS()
	return &d, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Domain, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, domain, verification_token, verified_at, created_at
		FROM tenant.domains WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Domain, 0)
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.Domain, &d.VerificationToken, &d.VerifiedAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.fillDNS()
		out = append(out, d)
	}
	return out, rows.Err()
}

// Verify looks up the DNS TXT record and, if the token is present, marks the
// domain verified. A missing record returns a friendly 422 (DNS may still be
// propagating); an already-verified-by-another-tenant collision returns 409.
func (s *Service) Verify(ctx context.Context, id, tenantID uuid.UUID) (*Domain, error) {
	var d Domain
	err := s.pool.QueryRow(ctx, `
		SELECT id, domain, verification_token, verified_at, created_at
		FROM tenant.domains WHERE id = $1 AND tenant_id = $2
	`, id, tenantID).Scan(&d.ID, &d.Domain, &d.VerificationToken, &d.VerifiedAt, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if d.VerifiedAt != nil {
		d.fillDNS()
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

	err = s.pool.QueryRow(ctx, `
		UPDATE tenant.domains SET verified_at = NOW()
		WHERE id = $1 AND tenant_id = $2
		RETURNING id, domain, verification_token, verified_at, created_at
	`, id, tenantID).Scan(&d.ID, &d.Domain, &d.VerificationToken, &d.VerifiedAt, &d.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "uq_verified_domain") {
			return nil, errs.ErrConflict.WithMessage("This domain is already verified by another organization.")
		}
		return nil, err
	}
	d.fillDNS()
	return &d, nil
}

func (s *Service) Remove(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM tenant.domains WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
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
