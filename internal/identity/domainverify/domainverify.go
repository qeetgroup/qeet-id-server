// Package domainverify lets an organization prove it owns an email domain with a DNS
// TXT record, checked only when an admin asks, and reports the provisioning
// state of its custom login hostname. A verified domain with SSO on sends
// everyone on it to the organization's identity provider (see capture.go).
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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// dnsHostPrefix is the subdomain the TXT record lives under, so verification
// never clobbers an organization's apex TXT records (SPF, etc.).
const dnsHostPrefix = "_qeet-verification."

// Service manages the domains. web checks a custom login hostname over HTTPS;
// owners decides who may name break-glass members.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	resolver Resolver
	web      *http.Client
	gate     entitlements.PlanGate
	owners   OwnerChecker
	// memberPermissions are all a member may hold without being an
	// administrator for domain capture.
	memberPermissions []string
}

// Deps are what the domain verification service is built from.
type Deps struct {
	Gate   entitlements.PlanGate // decides whether an organization's plan includes custom domains
	Owners OwnerChecker          // decides who may name break-glass members
	// MemberPermissions are all a member may hold without being an
	// administrator single sign-on doesn't adopt by address (identitylink's);
	// any other permission, and the owner role, make one.
	MemberPermissions []string
	// Outbound is where a check of a custom login hostname may go (nil:
	// public addresses over https).
	Outbound *egress.Policy
	// Resolver is where verification looks up TXT records (nil: the system
	// resolver).
	Resolver Resolver
}

// NewService returns the domain verification service built from d.
func NewService(pool *pgxpool.Pool, d Deps) (*Service, error) {
	switch {
	case d.Gate == nil:
		return nil, errors.New("domainverify: the domain service needs a plan gate")
	case d.Owners == nil:
		return nil, errors.New("domainverify: the domain service needs an owner check")
	case len(d.MemberPermissions) == 0:
		return nil, errors.New("domainverify: the domain service needs the member permissions")
	}
	var resolver Resolver = net.DefaultResolver
	if d.Resolver != nil {
		resolver = d.Resolver
	}
	return &Service{pool: pool, q: dbgen.New(pool), resolver: resolver,
		web: loginProbeClient(egress.PublicPolicy(d.Outbound)), gate: d.Gate, owners: d.Owners,
		memberPermissions: d.MemberPermissions}, nil
}

// Resolver looks up the TXT records at a DNS name.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// WithResolver returns a copy of s that looks up TXT records with r, for a
// tool that answers them itself.
func (s *Service) WithResolver(r Resolver) *Service {
	c := *s
	c.resolver = r
	return &c
}

// Domain is a domain an organization has claimed, and whether it is verified.
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

// rowToDomain builds a Domain from the columns the generated InsertDomain,
// GetDomainForVerify and MarkDomainVerified rows share.
func rowToDomain(id uuid.UUID, domain, token string, verifiedAt *time.Time, createdAt time.Time) Domain {
	d := Domain{
		ID:                id,
		Domain:            domain,
		VerificationToken: token,
		VerifiedAt:        verifiedAt,
		CreatedAt:         createdAt,
	}
	d.fillDNS()
	d.deriveStatus()
	return d
}

// Add registers a domain for an organization and returns the DNS record to publish,
// recorded as actor's.
func (s *Service) Add(ctx context.Context, organizationID uuid.UUID, raw string, actor audit.Actor) (*Domain, error) {
	// Plan gate: custom (verified) domains are a paid feature.
	allowed, err := s.gate.FeatureAllowed(ctx, organizationID, "custom_domain")
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "custom_domain"})
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
		OrganizationID:    organizationID,
		Domain:            domain,
		VerificationToken: token,
	})
	if err != nil {
		if strings.Contains(err.Error(), "uq_organization_domain") {
			return nil, ErrExists
		}
		return nil, err
	}
	d := rowToDomain(row.ID, row.Domain, row.VerificationToken, row.VerifiedAt, row.CreatedAt)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "domain.created", "domain", d.ID, map[string]any{"domain": d.Domain})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: d.ID, Topic: "domain.events", EventType: "domain.created", Payload: map[string]any{"domain_id": d.ID, "organization_id": organizationID, "domain": d.Domain}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &d, nil
}

// domainWithStatus builds a Domain from a row that also carries its switches
// and the outcome of its last check.
func domainWithStatus(row dbgen.ListDomainsRow) Domain {
	d := Domain{
		ID: row.ID, Domain: row.Domain, VerificationToken: row.VerificationToken, VerifiedAt: row.VerifiedAt,
		CreatedAt: row.CreatedAt, LastCheckedAt: row.LastCheckedAt, LastError: row.LastError,
		SSOEnabled: row.SsoEnabled, JITEnabled: row.JitEnabled,
	}
	d.fillDNS()
	d.deriveStatus()
	return d
}

// List returns the organization's domains with their settings and the outcome of the
// last verification attempt.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Domain, error) {
	rows, err := s.q.ListDomains(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Domain, 0, len(rows))
	for _, row := range rows {
		out = append(out, domainWithStatus(row))
	}
	return out, nil
}

// UpdateSettings toggles the per-domain switches.
func (s *Service) UpdateSettings(
	ctx context.Context, id, organizationID uuid.UUID,
	sso, jit *bool, actor audit.Actor,
) (*Domain, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row, err := s.q.WithTx(tx).UpdateDomainSettings(ctx, dbgen.UpdateDomainSettingsParams{
		SsoEnabled: sso, JitEnabled: jit, ID: id, OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d := domainWithStatus(dbgen.ListDomainsRow(row))

	if err := audit.Record(ctx, tx, actor.Event(organizationID, "domain.settings_updated", "domain", d.ID,
		map[string]any{"domain": d.Domain, "sso": d.SSOEnabled, "jit": d.JITEnabled})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &d, nil
}

// Verify marks the domain verified if its DNS TXT record holds the token. A
// failed check is recorded and returns the retryable
// ErrDomainVerifyDNSRecordMissing; a domain another organization has verified returns
// ErrDomainVerifyClaimedByOther.
func (s *Service) Verify(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) (*Domain, error) {
	row, err := s.q.GetDomainForVerify(ctx, dbgen.GetDomainForVerifyParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
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
		if uerr := s.q.RecordDomainCheck(ctx, dbgen.RecordDomainCheckParams{LastError: &reason, ID: id, OrganizationID: organizationID}); uerr != nil {
			return nil, uerr
		}
		return nil, errs.ErrDomainVerifyDNSRecordMissing
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.q.WithTx(tx).RecordDomainCheck(ctx, dbgen.RecordDomainCheckParams{ID: id, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	updated, err := s.q.WithTx(tx).MarkDomainVerified(ctx, dbgen.MarkDomainVerifiedParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		if strings.Contains(err.Error(), "uq_verified_domain") {
			return nil, errs.ErrDomainVerifyClaimedByOther
		}
		return nil, err
	}
	verified := rowToDomain(updated.ID, updated.Domain, updated.VerificationToken, updated.VerifiedAt, updated.CreatedAt)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "domain.verified", "domain", verified.ID, map[string]any{"domain": verified.Domain})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: verified.ID, Topic: "domain.events", EventType: "domain.verified", Payload: map[string]any{"domain_id": verified.ID, "organization_id": organizationID, "domain": verified.Domain}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &verified, nil
}

// Remove deletes one of the organization's domains, recorded as actor's.
func (s *Service) Remove(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteDomain(ctx, dbgen.DeleteDomainParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "domain.deleted", "domain", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "domain.events", EventType: "domain.deleted", Payload: map[string]any{"domain_id": id, "organization_id": organizationID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
