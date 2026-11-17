// Command seed fills a development database with production-shaped demo data:
// Qeet Group and customer organizations of every plan, size and stage, their
// people, connections, applications and integrations, and months of
// sign-in and audit history. It drives the API's own services, so hashes,
// encryption and permissions are real; history the API only writes as it
// happens is written directly and the audit chains rehashed. A developer's
// workstation (make seed) and the kit's DEV only.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/accounts"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/activity"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/census"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/connections"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/integrations"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/security"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// seedPassword is every seeded account's password.
const seedPassword = "Password123!"

// kept are the tables a reset leaves alone: the schema version, the signing
// keys sealed with this machine's vault key, and the built-in catalogues.
var kept = map[string]bool{
	"public.schema_migrations":     true,
	"platform.jwt_signing_keys":    true,
	"platform.billing_plans":       true,
	"platform.billing_plan_prices": true,
	"rbac.permissions":             true,
}

func main() {
	reset := flag.Bool("reset", false, "empty the database (dev only) before seeding")
	flag.Parse()
	started := time.Now()

	cfg, err := config.Load()
	world.Must(err, "load config")
	// Every seeded account shares one known password, so the seed runs only on
	// a developer's workstation and in the kit's DEV, never in TEST, STAGING or
	// production.
	kitDev := cfg.ServiceEnv == config.EnvLocal && cfg.ServiceProfile == "dev"
	if !cfg.IsDev() && !kitDev {
		log.Fatalf("seed: refusing to run with SERVICE_ENV=%q SERVICE_PROFILE=%q (a workstation or the kit's DEV only)", cfg.ServiceEnv, cfg.ServiceProfile)
	}
	// Without a fixed vault key the seed and the API would each make their own,
	// and the API couldn't read anything the seed encrypted.
	if cfg.SecretsProvider == "static" && cfg.SecretsKey == "" {
		log.Fatal("seed: set SECRETS_KEY in .env (any base64 32-byte key, e.g. `openssl rand -base64 32`) so the API can read what the seed encrypts")
	}
	// Bring the schema up to date first, as the API does at start, so a fresh
	// database (make db-reset) can be seeded straight away.
	world.Must(migrations.Run(cfg.DBURL), "run database migrations")
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	world.Must(err, "connect db")
	defer pool.Close()
	admin, err := pgxpool.New(ctx, cfg.DBURL)
	world.Must(err, "connect db as its owner")
	defer admin.Close()

	if *reset {
		empty(ctx, admin)
		fmt.Println("• emptied the database")
	} else {
		var n int
		world.Must(admin.QueryRow(ctx, `SELECT count(*) FROM organization.organizations`).Scan(&n), "count organisations")
		if n > 0 {
			log.Fatal("seed: the database already has organisations; run `make seed-reset` to start again")
		}
	}

	hash, err := password.Hash(seedPassword)
	world.Must(err, "hash password")
	w := world.New(ctx, cfg, pool, admin, seedPassword, hash)
	gettingStarted(w, cfg, kitDev)

	steps := []struct {
		name string
		run  func(*world.World)
	}{
		{"organisations, people, roles and groups", census.Seed},
		{"settings, account states and invitations", accounts.Seed},
		{"applications, SSO, directories and SCIM", connections.Seed},
		{"API keys, webhooks, agents and policies", integrations.Seed},
		{"second factors, devices and threats", security.Seed},
		{"sessions, sign-ins, audit and billing history", activity.Seed},
	}
	for _, s := range steps {
		t := time.Now()
		s.run(w)
		fmt.Printf("• %-45s %5.1fs\n", s.name, time.Since(t).Seconds())
	}

	w.Rechain()
	rows := w.VerifyChains()
	fmt.Printf("• audit chains rehashed and verified (%d rows)\n", rows)

	for _, o := range w.Orgs {
		for _, p := range o.People {
			if p.Login != "" {
				w.Note("Test accounts (password "+seedPassword+")", "%-40s %-20s %s", p.Email, o.Spec.Name, p.Login)
			}
		}
	}
	w.PrintSummary()
	fmt.Printf("\n✅ Seed complete in %s.\n", time.Since(started).Round(time.Second))
}

// empty truncates every table except the kept ones.
func empty(ctx context.Context, admin *pgxpool.Pool) {
	rows, err := admin.Query(ctx, `
		SELECT table_schema || '.' || table_name FROM information_schema.tables
		WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema')`)
	world.Must(err, "list tables")
	var tables []string
	for rows.Next() {
		var t string
		world.Must(rows.Scan(&t), "scan table")
		if !kept[t] {
			parts := strings.SplitN(t, ".", 2)
			tables = append(tables, fmt.Sprintf(`"%s"."%s"`, parts[0], parts[1]))
		}
	}
	rows.Close()
	_, err = admin.Exec(ctx, "TRUNCATE TABLE "+strings.Join(tables, ", ")+" RESTART IDENTITY CASCADE")
	world.Must(err, "empty the database")
}

// gettingStarted opens the summary with where everything runs and what a
// tester meets first: the kit's DEV addresses there, the workstation's
// otherwise.
func gettingStarted(w *world.World, cfg *config.Config, kitDev bool) {
	const section = "Before you start"
	if kitDev {
		mail := strings.Replace(cfg.AppBaseURL, "://console.", "://mail.", 1)
		w.Note(section, "Console  %-34s  sign in with a test account below", cfg.AppBaseURL)
		w.Note(section, "Hosted   %-34s  the hosted sign-in pages; open an app's authorize URL below", cfg.LoginBaseURL)
		w.Note(section, "Mail     %-34s  codes, magic links, invitations and resets land here", mail)
	} else {
		w.Note(section, "API      make dev                (http://localhost:%s)", cfg.HTTPPort)
		w.Note(section, "Console  %-22s  sign in with a test account below", cfg.AppBaseURL)
		w.Note(section, "Hosted   %-22s  the hosted sign-in pages; open an app's authorize URL below", cfg.LoginBaseURL)
		w.Note(section, "Mail     http://localhost:8025  (Mailpit) — codes, magic links, invitations and resets land here")
	}
	w.Note(section, "A first sign-in from a browser the account hasn't used asks for a code sent by email: read it in the mail inbox.")
	again := "make seed-reset"
	if kitDev {
		again = "the kit's DEV seed command"
	}
	w.Note(section, "Every account's password is %s. Re-run with %s: it empties the database first.", w.Password, again)
}
