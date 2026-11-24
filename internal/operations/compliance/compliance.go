// Package compliance answers for an organization's SOC 2 and ISO 27001
// controls: evidence runs that check its live state against each control,
// the person who owns each control, and the external audits and certificates
// it records. Each run, owner and audit change is audited.
package compliance

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/compliance/dbgen"
)

// EvidenceService generates compliance evidence by running live control checks
// against an organization's system state, and stores the results.
type EvidenceService struct {
	pool          *pgxpool.Pool
	q             *dbgen.Queries
	verifier      *audit.Verifier
	breachEnabled bool
}

// NewEvidenceService returns an EvidenceService. breachEnabled reports whether
// the platform's breached-password (HIBP) check is on, for the control that
// covers it.
func NewEvidenceService(pool *pgxpool.Pool, verifier *audit.Verifier, breachEnabled bool) *EvidenceService {
	return &EvidenceService{pool: pool, q: dbgen.New(pool), verifier: verifier, breachEnabled: breachEnabled}
}
