package compliance

// Compliance evidence for SOC 2 and ISO 27001. Each control maps to a framework
// criterion (CC6.1, A.8.5, …), checks the organization's live state, and returns pass,
// fail or na with a readable explanation; each run is stored as a
// compliance_evidence_runs row.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/compliance/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ControlStatus is the outcome of one compliance control check.
type ControlStatus string

const (
	ControlPass ControlStatus = "pass" // live data confirmed the condition
	ControlFail ControlStatus = "fail" // live data showed the condition is not met
	ControlNA   ControlStatus = "na"   // the data could not tell, such as no rows yet
)

// ControlResult captures the outcome of one compliance control check.
type ControlResult struct {
	ID       string `json:"id"`       // stable control ID
	Name     string `json:"name"`     // display name
	Category string `json:"category"` // control category
	Criteria string `json:"criteria"` // framework reference code, such as "CC6.1" or "A.8.5"
	// Criteria2013 is an ISO control's ISO/IEC 27001:2013 Annex A reference,
	// for audits still on that revision; empty for SOC 2.
	Criteria2013 string        `json:"criteria_2013,omitempty"`
	Status       ControlStatus `json:"status"` // the check's result
	Detail       string        `json:"detail"` // what was found, in English; never empty
	// DetailCode and Params are what was found as a code with its values, and
	// Remedy what would make a failing control pass, for a console to word.
	DetailCode string         `json:"detail_code"`
	Params     map[string]any `json:"params,omitempty"`
	Remedy     string         `json:"remedy,omitempty"`
	// FailingSince is when the control started failing, run after run.
	FailingSince *time.Time `json:"failing_since,omitempty"`
	// Owner is who the organization has made answer for the control, now.
	Owner *ControlOwner `json:"owner,omitempty"`
}

// EvidenceRun is one generated evidence snapshot for an organization+framework pair.
// Controls is populated on GetRun; it is omitted from list responses.
type EvidenceRun struct {
	ID             uuid.UUID       `json:"id"`
	OrganizationID uuid.UUID       `json:"organization_id"`
	Framework      string          `json:"framework"`
	GeneratedAt    time.Time       `json:"generated_at"`
	GeneratedBy    *uuid.UUID      `json:"generated_by,omitempty"`
	PassCount      int             `json:"pass_count"`
	FailCount      int             `json:"fail_count"`
	NACount        int             `json:"na_count"`
	Controls       []ControlResult `json:"controls,omitempty"`
}

// Generate runs every control of framework against the organization's live state and
// stores the run, recorded as actor's, in one transaction. It returns the run
// with its control results.
func (s *EvidenceService) Generate(ctx context.Context, organizationID uuid.UUID, framework string, actor audit.Actor) (*EvidenceRun, error) {
	controls, ok := controlsByFramework[framework]
	if !ok {
		return nil, ErrFrameworkInvalid
	}

	failingSince, err := s.failingSince(ctx, organizationID, framework)
	if err != nil {
		return nil, err
	}
	results := s.runControls(ctx, organizationID, controls, failingSince)
	passCount, failCount, naCount := tallyResults(results)

	controlsJSON, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	// Store the run and its audit event in one transaction.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row, err := dbgen.New(tx).InsertEvidenceRun(ctx, dbgen.InsertEvidenceRunParams{
		OrganizationID: organizationID,
		Framework:      framework,
		GeneratedBy:    actor.UserID,
		PassCount:      passCount,
		FailCount:      failCount,
		NaCount:        naCount,
		Controls:       controlsJSON,
	})
	if err != nil {
		return nil, err
	}

	run := EvidenceRun{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		Framework:      row.Framework,
		GeneratedAt:    row.GeneratedAt,
		GeneratedBy:    row.GeneratedBy,
		PassCount:      int(row.PassCount),
		FailCount:      int(row.FailCount),
		NACount:        int(row.NaCount),
	}

	if err := audit.Record(ctx, tx, actor.Event(organizationID, "compliance.evidence_generated", "compliance_evidence_run", run.ID, map[string]any{
		"framework":  framework,
		"pass_count": passCount,
		"fail_count": failCount,
		"na_count":   naCount,
	})); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	run.Controls = results
	if err := s.withOwners(ctx, organizationID, run.Controls); err != nil {
		return nil, err
	}
	return &run, nil
}

// failingSince is when each control that failed in the organization's last run
// of framework started failing: a control failing in that run too has been
// failing since then.
func (s *EvidenceService) failingSince(ctx context.Context, organizationID uuid.UUID, framework string) (map[string]time.Time, error) {
	failingSince := map[string]time.Time{}
	if last, err := s.q.LatestEvidenceControls(ctx, dbgen.LatestEvidenceControlsParams{OrganizationID: organizationID, Framework: framework}); err == nil {
		var before []ControlResult
		if json.Unmarshal(last.Controls, &before) == nil {
			for _, c := range before {
				if c.Status != ControlFail {
					continue
				}
				since := last.GeneratedAt
				if c.FailingSince != nil {
					since = *c.FailingSince
				}
				failingSince[c.ID] = since
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return failingSince, nil
}

// runControls checks each of controls against the organization's live state. A
// failing control names its remedy and when it started failing: failingSince's
// time, or now for a control that newly fails.
func (s *EvidenceService) runControls(ctx context.Context, organizationID uuid.UUID, controls []control, failingSince map[string]time.Time) []ControlResult {
	now := time.Now().UTC()
	results := make([]ControlResult, 0, len(controls))
	for _, c := range controls {
		f := c.check(ctx, s, organizationID)
		result := ControlResult{
			ID:           c.id,
			Name:         c.name,
			Category:     c.category,
			Criteria:     c.criteria,
			Criteria2013: c.criteria2013,
			Status:       f.status,
			Detail:       f.detail,
			DetailCode:   f.code,
			Params:       f.params,
		}
		if f.status == ControlFail {
			result.Remedy = remedies[f.code]
			since, ok := failingSince[c.id]
			if !ok {
				since = now
			}
			result.FailingSince = &since
		}
		results = append(results, result)
	}
	return results
}

// withOwners sets each control's current owner in organizationID.
func (s *EvidenceService) withOwners(ctx context.Context, organizationID uuid.UUID, controls []ControlResult) error {
	owners, err := s.Owners(ctx, organizationID)
	if err != nil {
		return err
	}
	byControl := map[string]*ControlOwner{}
	for i := range owners {
		byControl[owners[i].ControlID] = &owners[i]
	}
	for i := range controls {
		controls[i].Owner = byControl[controls[i].ID]
	}
	return nil
}

// ListRuns returns the organization's 100 most recent runs of framework, newest
// first, without their controls; GetRun has the full report.
func (s *EvidenceService) ListRuns(ctx context.Context, organizationID uuid.UUID, framework string) ([]EvidenceRun, error) {
	rows, err := s.q.ListEvidenceRuns(ctx, dbgen.ListEvidenceRunsParams{
		OrganizationID: organizationID,
		Framework:      framework,
	})
	if err != nil {
		return nil, err
	}
	out := make([]EvidenceRun, 0, len(rows))
	for _, r := range rows {
		out = append(out, EvidenceRun{
			ID:             r.ID,
			OrganizationID: r.OrganizationID,
			Framework:      r.Framework,
			GeneratedAt:    r.GeneratedAt,
			GeneratedBy:    r.GeneratedBy,
			PassCount:      int(r.PassCount),
			FailCount:      int(r.FailCount),
			NACount:        int(r.NaCount),
		})
	}
	return out, nil
}

// GetRun returns one of the organization's evidence runs with its control results:
// the full evidence report.
func (s *EvidenceService) GetRun(ctx context.Context, organizationID, id uuid.UUID) (*EvidenceRun, error) {
	r, err := s.q.GetEvidenceRun(ctx, dbgen.GetEvidenceRunParams{
		ID:             id,
		OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	run := &EvidenceRun{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		Framework:      r.Framework,
		GeneratedAt:    r.GeneratedAt,
		GeneratedBy:    r.GeneratedBy,
		PassCount:      int(r.PassCount),
		FailCount:      int(r.FailCount),
		NACount:        int(r.NaCount),
	}
	if len(r.Controls) > 0 {
		if err := json.Unmarshal(r.Controls, &run.Controls); err != nil {
			return nil, err
		}
	}
	if err := s.withOwners(ctx, organizationID, run.Controls); err != nil {
		return nil, err
	}
	return run, nil
}

// tallyResults counts the pass, fail and na results.
func tallyResults(results []ControlResult) (pass, fail, na int32) {
	for _, r := range results {
		switch r.Status {
		case ControlPass:
			pass++
		case ControlFail:
			fail++
		default:
			na++
		}
	}
	return
}
