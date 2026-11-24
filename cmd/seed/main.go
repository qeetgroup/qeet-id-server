// Command seed fills an empty development database with demo data: Qeet Group
// and customers of every plan and stage, their people, connections and
// integrations. It writes only through the server's services and handlers, so
// everything is real and dated now. A workstation and the kit's DEV only.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/accounts"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/census"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/connections"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/integrations"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/security"
	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// seedPassword is every seeded account's password.
const seedPassword = "Password123!"

func main() {
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
	// Without a fixed vault key the seed and the server would each make their
	// own, and the server couldn't read anything the seed encrypted.
	if cfg.SecretsProvider == "static" && cfg.SecretsKey == "" {
		log.Fatal("seed: set SECRETS_KEY in .env (any base64 32-byte key, e.g. `openssl rand -base64 32`) so the API can read what the seed encrypts")
	}
	// Bring the schema up to date first, as the server does at start, so a
	// fresh database can be seeded straight away.
	world.Must(migrations.Run(cfg.DBURL), "run database migrations")
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	world.Must(err, "connect db")
	defer pool.Close()

	hash, err := password.Hash(seedPassword)
	world.Must(err, "hash password")
	w := world.New(ctx, cfg, pool, seedPassword, hash)
	again := "make seed-reset"
	if kitDev {
		again = "the kit's DEV seed command"
	}
	if _, err := w.Deps.Organization.Repo.GetBySlug(ctx, "qeet"); !errors.Is(err, errs.ErrNotFound) {
		world.Must(err, "look for seeded data")
		log.Fatalf("seed: the database is already seeded; run %s to recreate it and seed again", again)
	}
	gettingStarted(w, kitDev, again)

	steps := []struct {
		name string
		run  func(*world.World)
	}{
		{"organizations, people, roles and groups", census.Seed},
		{"settings, account states and invitations", accounts.Seed},
		{"applications, SSO, directories and SCIM", connections.Seed},
		{"API keys, webhooks, agents and policies", integrations.Seed},
		{"second factors, address rules, threats, sign-ins", security.Seed},
	}
	for _, s := range steps {
		t := time.Now()
		s.run(w)
		fmt.Printf("• %-50s %5.1fs\n", s.name, time.Since(t).Seconds())
	}
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

// gettingStarted opens the summary with where everything runs and what a
// tester meets first: the kit's DEV addresses there, the workstation's
// otherwise.
func gettingStarted(w *world.World, kitDev bool, again string) {
	const section = "Before you start"
	cfg := w.Cfg
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
	w.Note(section, "Every account's password is %s. Everything was written just now. To start again, run %s:", w.Password, again)
	w.Note(section, "it recreates the database, then seeds it.")
}
