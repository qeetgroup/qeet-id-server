// Package domainverify lets a tenant prove it owns an email domain with a DNS
// TXT record, checked only when an admin asks, and reports the DNS state of its
// custom login hostname.
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
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
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
	gate PlanGate
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), resolver: net.DefaultResolver}
}

// PlanGate reports whether a boolean plan feature is in the tenant's plan.
// Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// SetPlanGate sets the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g PlanGate) { s.gate = g }

type Domain struct {
	ID                uuid.UUID  `json:"id"`
	Domain            string     `json:"domain"`
	VerificationToken string     `json:"verification_token"`
	DNSRecordName     string     `json:"dns_record_name"`
	DNSRecordType     string     `json:"dns_record_type"`
	DNSRecordValue    string     `json:"dns_record_value"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`

	// LastCheckedAt/LastError record the most recent verification attempt, so
	// the console can tell "not checked yet" from "checked and it failed".
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	// Per-domain switches: verifying ownership doesn't itself opt a domain into
	// SSO routing or just-in-time provisioning.
	SSOEnabled bool `json:"sso_enabled"`
	JITEnabled bool `json:"jit_enabled"`
	IsDefault  bool `json:"is_default"`
	// Status is derived, never stored: verified | pending | attention.
	Status string `json:"status"`
}

// deriveStatus collapses the stored fields into the three states the console
// renders. "attention" is specifically a domain whose last check FAILED —
// distinct from one nobody has checked yet, which is simply pending.
func (d *Domain) deriveStatus() {
	switch {
	case d.VerifiedAt != nil:
		d.Status = "verified"
	case d.LastError != "":
		d.Status = "attention"
	default:
		d.Status = "pending"
	}
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
		if r != '.' && r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
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

// rowToDomain builds a Domain from the columns the generated InsertDomain,
// GetDomainForVerify and MarkDomainVerified rows share.
func rowToDomain(id uuid.UUID, domain, token string, verifiedAt pgtype.Timestamptz, createdAt time.Time) Domain {
	d := Domain{
		ID:                id,
		Domain:            domain,
		VerificationToken: token,
		VerifiedAt:        pgtypeToTimePtr(verifiedAt),
		CreatedAt:         createdAt,
	}
	d.fillDNS()
	d.deriveStatus()
	return d
}

// Add registers a domain for a tenant and returns the DNS record to publish.
func (s *Service) Add(ctx context.Context, tenantID uuid.UUID, raw string) (*Domain, error) {
	return s.AddWithActor(ctx, tenantID, raw, audit.Actor{Type: "system"})
}

func (s *Service) AddWithActor(ctx context.Context, tenantID uuid.UUID, raw string, actor audit.Actor) (*Domain, error) {
	// Plan gate: custom (verified) domains are a paid feature.
	if s.gate != nil {
		ok, err := s.gate.FeatureAllowed(ctx, tenantID, "custom_domain")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "custom_domain"})
		}
	}
	domain := normalizeDomain(raw)
	if !validDomain(domain) {
		return nil, errs.ErrDomainVerifyInvalidDomain
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).InsertDomain(ctx, dbgen.InsertDomainParams{
		TenantID:          tenantID,
		Domain:            domain,
		VerificationToken: token,
	})
	if err != nil {
		if strings.Contains(err.Error(), "uq_tenant_domain") {
			return nil, errs.ErrDomainVerifyExists
		}
		return nil, err
	}
	d := rowToDomain(row.ID, row.Domain, row.VerificationToken, row.VerifiedAt, row.CreatedAt)
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "domain.created", "domain", d.ID, map[string]any{"domain": d.Domain})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: d.ID, Topic: "domain.events", EventType: "domain.created", Payload: map[string]any{"domain_id": d.ID, "tenant_id": tenantID, "domain": d.Domain}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &d, nil
}

// List returns the tenant's domains with their settings and the outcome of the
// last verification attempt. It is hand-written SQL because the generated
// ListDomains doesn't select those columns.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Domain, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, domain, verification_token, verified_at, created_at,
		       last_checked_at, COALESCE(last_error, ''), sso_enabled, jit_enabled, is_default
		FROM tenant.domains
		WHERE tenant_id = $1
		ORDER BY is_default DESC, domain
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Domain, 0)
	for rows.Next() {
		var d Domain
		var verifiedAt, lastChecked *time.Time
		if err := rows.Scan(&d.ID, &d.Domain, &d.VerificationToken, &verifiedAt, &d.CreatedAt,
			&lastChecked, &d.LastError, &d.SSOEnabled, &d.JITEnabled, &d.IsDefault); err != nil {
			return nil, err
		}
		d.VerifiedAt, d.LastCheckedAt = verifiedAt, lastChecked
		d.fillDNS()
		d.deriveStatus()
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateSettings toggles the per-domain switches. Making a domain the default
// clears the previous one in the same transaction, so the partial unique index
// can never be violated by a straight UPDATE.
func (s *Service) UpdateSettings(
	ctx context.Context, id, tenantID uuid.UUID,
	sso, jit, isDefault *bool, actor audit.Actor,
) (*Domain, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if isDefault != nil && *isDefault {
		if _, err := tx.Exec(ctx,
			`UPDATE tenant.domains SET is_default = FALSE WHERE tenant_id = $1 AND is_default`,
			tenantID); err != nil {
			return nil, err
		}
	}

	var d Domain
	var verifiedAt, lastChecked *time.Time
	err = tx.QueryRow(ctx, `
		UPDATE tenant.domains SET
			sso_enabled = COALESCE($3, sso_enabled),
			jit_enabled = COALESCE($4, jit_enabled),
			is_default  = COALESCE($5, is_default)
		WHERE id = $1 AND tenant_id = $2
		RETURNING id, domain, verification_token, verified_at, created_at,
		          last_checked_at, COALESCE(last_error, ''), sso_enabled, jit_enabled, is_default
	`, id, tenantID, sso, jit, isDefault).
		Scan(&d.ID, &d.Domain, &d.VerificationToken, &verifiedAt, &d.CreatedAt,
			&lastChecked, &d.LastError, &d.SSOEnabled, &d.JITEnabled, &d.IsDefault)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrDomainVerifyNotFound
	}
	if err != nil {
		return nil, err
	}
	d.VerifiedAt, d.LastCheckedAt = verifiedAt, lastChecked
	d.fillDNS()
	d.deriveStatus()

	if err := audit.Record(ctx, tx, actor.Event(tenantID, "domain.settings_updated", "domain", d.ID,
		map[string]any{"domain": d.Domain, "sso": d.SSOEnabled, "jit": d.JITEnabled,
			"default": d.IsDefault})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &d, nil
}

// Verify marks the domain verified if its DNS TXT record holds the token. A
// failed check is recorded and returns the retryable
// ErrDomainVerifyDNSRecordMissing; a domain another tenant has verified returns
// ErrDomainVerifyClaimedByOther.
func (s *Service) Verify(ctx context.Context, id, tenantID uuid.UUID) (*Domain, error) {
	return s.VerifyWithActor(ctx, id, tenantID, audit.Actor{Type: "system"})
}

func (s *Service) VerifyWithActor(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) (*Domain, error) {
	row, err := s.q.GetDomainForVerify(ctx, dbgen.GetDomainForVerifyParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrDomainVerifyNotFound
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
		// Stamp the failed attempt before returning. Without this the domain
		// stays indistinguishable from one nobody has checked yet, and the
		// "Attention required" state could never be reached.
		reason := "DNS TXT record not found"
		if lerr != nil {
			reason = "DNS lookup failed"
		}
		if _, uerr := s.pool.Exec(ctx,
			`UPDATE tenant.domains SET last_checked_at = NOW(), last_error = $3
			 WHERE id = $1 AND tenant_id = $2`, id, tenantID, reason); uerr != nil {
			return nil, uerr
		}
		return nil, errs.ErrDomainVerifyDNSRecordMissing
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`UPDATE tenant.domains SET last_checked_at = NOW(), last_error = NULL
		 WHERE id = $1 AND tenant_id = $2`, id, tenantID); err != nil {
		return nil, err
	}
	updated, err := s.q.WithTx(tx).MarkDomainVerified(ctx, dbgen.MarkDomainVerifiedParams{ID: id, TenantID: tenantID})
	if err != nil {
		if strings.Contains(err.Error(), "uq_verified_domain") {
			return nil, errs.ErrDomainVerifyClaimedByOther
		}
		return nil, err
	}
	verified := rowToDomain(updated.ID, updated.Domain, updated.VerificationToken, updated.VerifiedAt, updated.CreatedAt)
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "domain.verified", "domain", verified.ID, map[string]any{"domain": verified.Domain})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: verified.ID, Topic: "domain.events", EventType: "domain.verified", Payload: map[string]any{"domain_id": verified.ID, "tenant_id": tenantID, "domain": verified.Domain}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &verified, nil
}

func (s *Service) Remove(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.RemoveWithActor(ctx, id, tenantID, audit.Actor{Type: "system"})
}

func (s *Service) RemoveWithActor(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteDomain(ctx, dbgen.DeleteDomainParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrDomainVerifyNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "domain.deleted", "domain", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "domain.events", EventType: "domain.deleted", Payload: map[string]any{"domain_id": id, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type Handler struct {
	Service *Service
}

func actorOf(r *http.Request) audit.Actor {
	actor := audit.Actor{Type: "system", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if principal := httpx.PrincipalFromCtx(r.Context()); principal != nil {
		actor.UserID = principal.UserID
		if principal.ActorType != "" {
			actor.Type = principal.ActorType
		}
	}
	return actor
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/domains", h.list)
	r.Post("/tenants/{tenantID}/domains", h.add)
	r.Post("/tenants/{tenantID}/domains/{id}/verify", h.verify)
	r.Get("/tenants/{tenantID}/login-domain", h.loginDomain)
	r.Patch("/tenants/{tenantID}/domains/{id}", h.updateSettings)
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
	d, err := h.Service.AddWithActor(r.Context(), tenantID, in.Domain, actorOf(r))
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
	d, err := h.Service.VerifyWithActor(r.Context(), id, tenantID, actorOf(r))
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
	if err := h.Service.RemoveWithActor(r.Context(), id, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type updateSettingsInput struct {
	SSOEnabled *bool `json:"sso_enabled"`
	JITEnabled *bool `json:"jit_enabled"`
	IsDefault  *bool `json:"is_default"`
}

func (h *Handler) updateSettings(w http.ResponseWriter, r *http.Request) {
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
	var in updateSettingsInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.Service.UpdateSettings(r.Context(), id, tenantID, in.SSOEnabled, in.JITEnabled,
		in.IsDefault, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}
