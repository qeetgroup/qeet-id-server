//go:build integration

// Package integration runs domain flows against a real, ephemeral Postgres
// spun up via testcontainers and migrated with the repo's own migration files.
// It is gated behind the `integration` build tag so the default `go test ./...`
// stays Docker-free; run it with `make test-integration`. If Docker isn't
// reachable the suite skips rather than fails.
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

// testPool is the shared pool for the whole package; nil means setup was
// skipped (no Docker), in which case requireDB skips each test.
var testPool *pgxpool.Pool

// testDSN is the container's connection string, exposed so a test can build a
// deliberately constrained pool (see the MFA pool-exhaustion test).
var testDSN string

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()

	// Ryuk (testcontainers' reaper) can't be reached on some macOS/colima
	// Docker setups and then blocks startup indefinitely. We clean up
	// explicitly via defer ctr.Terminate, so disable it for a hang-free run.
	if os.Getenv("TESTCONTAINERS_RYUK_DISABLED") == "" {
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}

	scripts, err := upMigrations()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: cannot locate migrations: %v\n", err)
		return 1
	}

	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("qeet_id_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.WithInitScripts(scripts...),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		// No Docker / can't start a container: skip rather than fail so the
		// suite is safe to run anywhere.
		fmt.Fprintf(os.Stderr, "integration: skipping (container start failed): %v\n", err)
		return 0
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: connection string: %v\n", err)
		return 1
	}
	testDSN = dsn
	testPool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: pool: %v\n", err)
		return 1
	}
	defer testPool.Close()

	return m.Run()
}

// upMigrations returns the absolute paths of every *.up.sql migration, sorted
// so Postgres' init-script runner applies them in version order.
func upMigrations() ([]string, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "internal", "platform", "database", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, filepath.Join(dir, e.Name()))
		}
	}
	if len(ups) == 0 {
		return nil, fmt.Errorf("no .up.sql files in %s", dir)
	}
	sort.Strings(ups)
	return ups, nil
}

// requireDB skips the calling test when no container is available.
func requireDB(t *testing.T) {
	t.Helper()
	if testPool == nil {
		t.Skip("integration: no database (Docker unavailable)")
	}
}

func testEnvelope(t *testing.T) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("create test envelope: %v", err)
	}
	return box
}

// uniqueSlug returns a short, collision-resistant identifier for test data.
func uniqueSlug(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
}

// createTenant inserts a bare tenant row and returns its id.
func createTenant(t *testing.T, ctx context.Context, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(ctx, `
		INSERT INTO tenant.tenants (slug, name, plan, region)
		VALUES ($1, $2, 'free', 'us-east-1') RETURNING id
	`, slug, slug).Scan(&id)
	if err != nil {
		t.Fatalf("createTenant: %v", err)
	}
	return id
}

func addTenantMembership(t *testing.T, ctx context.Context, userID, tenantID uuid.UUID) {
	t.Helper()
	var roleID uuid.UUID
	err := testPool.QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name, description, is_system)
		VALUES ($1, $2, 'integration membership', FALSE)
		RETURNING id
	`, tenantID, uniqueSlug("member")).Scan(&roleID)
	if err != nil {
		t.Fatalf("create membership role: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO rbac.user_roles (user_id, tenant_id, role_id)
		VALUES ($1, $2, $3)
	`, userID, tenantID, roleID); err != nil {
		t.Fatalf("assign tenant membership: %v", err)
	}
}

// --- MFA attempt-budget helpers ---
//
// The MFA service takes a pre-reserved attempt slot rather than claiming one
// itself, so the budget's own transaction never nests inside the caller's (see
// mfa.Attempt). These mirror what the HTTP handlers do — reserve first, then
// run the verification in its own transaction — so tests exercise the real
// ordering instead of a shape production never uses.

func mfaConfirmEnroll(ctx context.Context, svc *mfa.Service, userID uuid.UUID, code string) ([]string, error) {
	attempt, err := svc.ReserveAttempt(ctx, userID, mfa.PurposeTOTPEnroll)
	if err != nil {
		return nil, err
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	out, err := svc.ConfirmEnroll(ctx, tx, attempt, code)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func mfaVerify(ctx context.Context, svc *mfa.Service, userID uuid.UUID, code string) (*mfa.VerifyResult, error) {
	attempt, err := svc.ReserveAttempt(ctx, userID, mfa.PurposeFactorVerify)
	if err != nil {
		return nil, err
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	out, err := svc.Verify(ctx, tx, attempt, code)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func mfaEnrollOTPConfirm(ctx context.Context, svc *mfa.Service, userID, factorID uuid.UUID, code string) error {
	attempt, err := svc.ReserveAttempt(ctx, userID, mfa.PurposeOTPEnroll(factorID))
	if err != nil {
		return err
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := svc.EnrollOTPConfirm(ctx, tx, attempt, factorID, code); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func mfaVerifyOTP(ctx context.Context, svc *mfa.Service, userID uuid.UUID, code string) (bool, error) {
	attempt, err := svc.ReserveAttempt(ctx, userID, mfa.PurposeOTPVerify)
	if err != nil {
		return false, err
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	ok, err := svc.VerifyOTP(ctx, tx, attempt, code)
	if err != nil || !ok {
		return false, err
	}
	return true, tx.Commit(ctx)
}
