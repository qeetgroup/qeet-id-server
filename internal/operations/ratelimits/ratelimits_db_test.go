//go:build integration

package ratelimits

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// limiter records the overrides applied to it and cleared from it.
type limiter struct{ applied, cleared int }

func (l *limiter) ApplyOverride(uuid.UUID, float64, int) { l.applied++ }
func (l *limiter) ClearOverride(uuid.UUID)               { l.cleared++ }
func (l *limiter) GetAll(context.Context, *pgxpool.Pool) ([]ratelimit.OrganizationLimit, error) {
	return nil, nil
}

// refuseAudit makes the organization's audit writes of action fail until t
// ends, as an audit store that is down would.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	owner, name := dbtest.Owner(t), "refuse_"+strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := owner.Exec(dbtest.Context(t), `
		CREATE FUNCTION pg_temp.`+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit store down'; END $$;
		CREATE TRIGGER `+name+` BEFORE INSERT ON audit.events FOR EACH ROW
		WHEN (NEW.organization_id = '`+organization.String()+`' AND NEW.action = '`+action+`') EXECUTE FUNCTION pg_temp.`+name+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), `DROP FUNCTION pg_temp.`+name+`() CASCADE`) })
}

// TestOverrideChangesCommitWithTheirAuditEvents checks that setting and
// clearing an organization's overrides are each undone, and never reach the
// limiters, when their audit event can't be written, and are recorded once
// when it can.
func TestOverrideChangesCommitWithTheirAuditEvents(t *testing.T) {
	ctx := dbtest.Context(t)
	lim := &limiter{}
	h := &Handler{Pool: dbtest.Pool(t), OrganizationLim: lim, UserLim: lim, APIKeyLim: lim}
	rate, capacity := 5.0, 10
	in := OrganizationLimits{Organization: LimitConfig{Rate: &rate, Capacity: &capacity}}
	actor := audit.Actor{Type: "system"}
	overrides := func(organization uuid.UUID) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM platform.rate_limit_overrides WHERE organization_id = $1`, organization)
	}
	events := func(organization uuid.UUID, action string) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2`, organization, action)
	}

	refused := dbtest.Organization(t)
	refuseAudit(t, refused, "rate_limits.updated")
	if err := h.save(ctx, refused, in, actor); err == nil {
		t.Fatal("set overrides while their audit event can't be written: no error")
	}
	if overrides(refused) != 0 || lim.applied != 0 {
		t.Errorf("after a failed audit write: %d overrides stored, %d applied; want none", overrides(refused), lim.applied)
	}

	organization := dbtest.Organization(t)
	if err := h.save(ctx, organization, in, actor); err != nil {
		t.Fatal(err)
	}
	if overrides(organization) != 1 || lim.applied != 1 || events(organization, "rate_limits.updated") != 1 {
		t.Errorf("after setting one: %d stored, %d applied, %d recorded; want 1 each",
			overrides(organization), lim.applied, events(organization, "rate_limits.updated"))
	}
	refuseAudit(t, organization, "rate_limits.deleted")
	if err := h.clear(ctx, organization, actor); err == nil {
		t.Fatal("clear overrides while their audit event can't be written: no error")
	}
	if overrides(organization) != 1 || lim.cleared != 0 {
		t.Errorf("after a failed clear: %d overrides stored, %d cleared; want 1 and none", overrides(organization), lim.cleared)
	}
}
