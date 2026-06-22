// Command seed populates the database with a realistic demo workspace so the
// admin UI has data to browse. It uses the app's own services/repositories, so
// passwords are real bcrypt (you can log in), users appear via rbac membership,
// and audit rows are properly hash-chained.
//
//	make seed          # seed on top of whatever exists
//	make seed-reset    # wipe (dev only) then seed a clean dataset
//
// Everyone shares the password below.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/internal/apikey"
	"github.com/qeetgroup/qeet-id/internal/audit"
	"github.com/qeetgroup/qeet-id/internal/auth"
	"github.com/qeetgroup/qeet-id/internal/branding"
	"github.com/qeetgroup/qeet-id/internal/config"
	"github.com/qeetgroup/qeet-id/internal/group"
	"github.com/qeetgroup/qeet-id/internal/platform/db"
	"github.com/qeetgroup/qeet-id/internal/platform/password"
	"github.com/qeetgroup/qeet-id/internal/platform/tokens"
	"github.com/qeetgroup/qeet-id/internal/policy"
	"github.com/qeetgroup/qeet-id/internal/rbac"
	"github.com/qeetgroup/qeet-id/internal/social"
	"github.com/qeetgroup/qeet-id/internal/tenant"
	"github.com/qeetgroup/qeet-id/internal/user"
	"github.com/qeetgroup/qeet-id/internal/webhook"
)

const seedPassword = "Password123!"

func main() {
	reset := flag.Bool("reset", false, "wipe existing data (dev only) before seeding")
	flag.Parse()

	cfg, err := config.Load()
	must(err, "load config")

	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg.DBURL, cfg.DBMinConns, cfg.DBMaxConns)
	must(err, "connect db")
	defer pool.Close()

	if *reset {
		if cfg.ServiceEnv != "dev" {
			log.Fatalf("seed: refusing to -reset when SERVICE_ENV=%q (dev only)", cfg.ServiceEnv)
		}
		_, err := pool.Exec(ctx, `TRUNCATE TABLE audit.events, tenant.tenants, "user".users RESTART IDENTITY CASCADE`)
		must(err, "reset")
		fmt.Println("• wiped existing data")
	}

	inTx := func(what string, fn func(tx pgx.Tx) error) {
		tx, err := pool.Begin(ctx)
		must(err, "begin "+what)
		if err := fn(tx); err != nil {
			_ = tx.Rollback(ctx)
			must(err, what)
		}
		must(tx.Commit(ctx), "commit "+what)
	}

	signingKeyPEM := cfg.JWTSigningKey
	if signingKeyPEM == "" {
		k, genErr := tokens.GenerateES256KeyPEM()
		must(genErr, "generate ephemeral signing key")
		signingKeyPEM = k
	}
	issuer, err := tokens.NewIssuer(signingKeyPEM, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	must(err, "init issuer")
	userRepo := user.NewRepository(pool)
	tenantRepo := tenant.NewRepository(pool)
	rbacRepo := rbac.NewRepository(pool)
	must(rbacRepo.SeedBuiltins(ctx), "seed rbac builtins")
	rbacSvc := rbac.NewService(rbacRepo)
	authSvc := auth.NewService(pool, userRepo, issuer)
	groupSvc := group.NewService(pool)
	apikeySvc := apikey.NewService(pool)
	webhookSvc := webhook.NewService(pool)
	socialSvc := social.NewService(pool, authSvc, cfg.AppBaseURL)
	brandingRepo := branding.NewRepository(pool)
	policyRepo := policy.NewRepository(pool)

	pwHash, err := password.Hash(seedPassword)
	must(err, "hash password")

	// ---- Owner + primary tenant (Acme) ----
	// Signup creates a tenant-less identity; CreateWithOwner then makes them the
	// owner of Acme (owner role + membership + home tenant).
	_, owner, _, err := authSvc.Signup(ctx, auth.SignupInput{Email: "owner@acme.test", Password: seedPassword, DisplayName: "Olivia Owner"})
	must(err, "signup owner")
	acme, err := tenantRepo.CreateWithOwner(ctx, tenant.CreateInput{Slug: "acme", Name: "Acme Inc", Plan: "pro", Region: "us-east-1"}, owner.ID)
	must(err, "create tenant acme")

	actor := audit.Actor{UserID: &owner.ID, Type: "user"}

	// ---- Roles in Acme ----
	perms, err := rbacRepo.ListPermissions(ctx)
	must(err, "list permissions")
	adminRole, err := rbacSvc.CreateRole(ctx, acme.ID, "admin", "Full administrative access", actor)
	must(err, "create admin role")
	memberRole, err := rbacSvc.CreateRole(ctx, acme.ID, "member", "Standard member", actor)
	must(err, "create member role")
	for _, p := range perms {
		must(rbacSvc.GrantPermission(ctx, adminRole.ID, p.ID, actor), "grant admin perm")
	}
	// member is read-only: the four basic browse permissions only — nothing
	// sensitive (no audit/secrets/keys/connections/billing) and no writes.
	memberReads := map[string]bool{"tenant.read": true, "user.read": true, "role.read": true, "group.read": true}
	for _, p := range perms {
		if memberReads[p.Key] {
			must(rbacSvc.GrantPermission(ctx, memberRole.ID, p.ID, actor), "grant member perm")
		}
	}

	// ---- Member users in Acme (each gets a role -> appears in the users list) ----
	members := []struct {
		email, name string
		role        uuid.UUID
	}{
		{"alice@acme.test", "Alice Admin", adminRole.ID},
		{"bob@acme.test", "Bob Builder", memberRole.ID},
		{"carol@acme.test", "Carol Chen", memberRole.ID},
		{"dave@acme.test", "Dave Diaz", memberRole.ID},
	}
	users := map[string]*user.User{}
	for _, m := range members {
		u, err := userRepo.CreateWithCredential(ctx, user.CreateInput{TenantID: acme.ID, Email: m.email, DisplayName: m.name}, pwHash)
		must(err, "create user "+m.email)
		must(rbacSvc.AssignRole(ctx, u.ID, acme.ID, m.role, &owner.ID, actor), "assign role "+m.email)
		users[m.email] = u
	}

	// ---- Groups + members ----
	eng, err := groupSvc.Create(ctx, group.CreateInput{TenantID: acme.ID, Name: "Engineering", Description: "Product engineering"}, actor)
	must(err, "create group engineering")
	sales, err := groupSvc.Create(ctx, group.CreateInput{TenantID: acme.ID, Name: "Sales", Description: "Revenue team"}, actor)
	must(err, "create group sales")
	must(groupSvc.AddMember(ctx, eng.ID, owner.ID, acme.ID, actor), "group add owner")
	must(groupSvc.AddMember(ctx, eng.ID, users["alice@acme.test"].ID, acme.ID, actor), "group add alice")
	must(groupSvc.AddMember(ctx, eng.ID, users["carol@acme.test"].ID, acme.ID, actor), "group add carol")
	must(groupSvc.AddMember(ctx, sales.ID, users["bob@acme.test"].ID, acme.ID, actor), "group add bob")

	// ---- API keys ----
	for _, name := range []string{"CI pipeline", "Nightly backup"} {
		k, full, err := apikeySvc.Create(ctx, apikey.CreateInput{TenantID: acme.ID, UserID: &owner.ID, Name: name, Scopes: []string{"users:read", "audit:read"}})
		must(err, "create api key "+name)
		fmt.Printf("  • api key %-14q %s\n", k.Name, full)
	}

	// ---- Demo OIDC client for the Next.js example app (frontend/examples/nextjs-app) ----
	// Fixed client_id + dev secret so the example's committed .env.example works out
	// of the box. Dev-only (this whole seed is dev-only). RegisterClient mints random
	// ids/secrets, so we insert directly to pin known values.
	const exampleClientID = "qci_example_app"
	const exampleClientSecret = "example-app-dev-secret-change-me"
	exHash, err := password.Hash(exampleClientSecret)
	must(err, "hash example client secret")
	_, err = pool.Exec(ctx, `
		INSERT INTO auth.oidc_clients (
			tenant_id, client_id, client_secret_hash, type, name,
			redirect_uris, post_logout_uris, grant_types, scopes
		) VALUES ($1, $2, $3, 'confidential', 'Example Web App',
			$4, $5, '{authorization_code,refresh_token}', '{openid,profile,email}')
		ON CONFLICT (client_id) DO NOTHING
	`, acme.ID, exampleClientID, exHash,
		[]string{"http://localhost:3010/api/auth/callback"},
		[]string{"http://localhost:3010", "http://localhost:3010/"})
	must(err, "create example oidc client")
	fmt.Printf("  • oidc client  %-14q %s (secret: %s)\n", "Example Web App", exampleClientID, exampleClientSecret)

	// A PUBLIC client (no secret) for the React SPA example (frontend/examples/react-app),
	// which runs the Authorization-Code + PKCE flow entirely in the browser. The SPA's
	// origin must also be in ALLOWED_ORIGINS for the cross-origin token/userinfo calls.
	_, err = pool.Exec(ctx, `
		INSERT INTO auth.oidc_clients (
			tenant_id, client_id, client_secret_hash, type, name,
			redirect_uris, post_logout_uris, grant_types, scopes
		) VALUES ($1, $2, NULL, 'public', 'Example SPA (React)',
			$3, $4, '{authorization_code}', '{openid,profile,email}')
		ON CONFLICT (client_id) DO NOTHING
	`, acme.ID, "qci_example_spa",
		[]string{"http://localhost:3020/callback"},
		[]string{"http://localhost:3020", "http://localhost:3020/"})
	must(err, "create example spa oidc client")
	fmt.Printf("  • oidc client  %-14q %s (public, PKCE — no secret)\n", "Example SPA", "qci_example_spa")

	// ---- Webhooks ----
	inTx("webhook 1", func(tx pgx.Tx) error {
		_, e := webhookSvc.Create(ctx, tx, webhook.CreateInput{TenantID: acme.ID, URL: "https://hooks.acme.test/qeet", Events: []string{"user.created", "auth.login_succeeded"}})
		return e
	})
	inTx("webhook 2", func(tx pgx.Tx) error {
		_, e := webhookSvc.Create(ctx, tx, webhook.CreateInput{TenantID: acme.ID, URL: "https://example.com/webhook", Events: []string{}})
		return e
	})

	// ---- Social providers ----
	_, err = socialSvc.UpsertProvider(ctx, social.CreateProviderInput{TenantID: acme.ID, Provider: "google", ClientID: "google-client-id", ClientSecret: "google-secret", DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration"})
	must(err, "social google")
	_, err = socialSvc.UpsertProvider(ctx, social.CreateProviderInput{TenantID: acme.ID, Provider: "github", ClientID: "github-client-id", ClientSecret: "github-secret"})
	must(err, "social github")

	// ---- Branding + policy ----
	inTx("branding", func(tx pgx.Tx) error {
		return brandingRepo.Upsert(ctx, tx, branding.Branding{
			TenantID:         acme.ID,
			PrimaryColor:     ptr("#4f46e5"),
			SecondaryColor:   ptr("#0ea5e9"),
			EmailFromName:    ptr("Acme Security"),
			EmailFromAddress: ptr("security@acme.test"),
			Settings:         map[string]any{"login_headline": "Welcome back to Acme"},
		})
	})
	inTx("policy", func(tx pgx.Tx) error {
		return policyRepo.Upsert(ctx, tx, policy.Policy{
			TenantID:           acme.ID,
			IPAllowlist:        []string{},
			IPDenylist:         []string{},
			PasswordMinLength:  10,
			PasswordComplexity: "standard",
			SessionMaxAge:      24 * time.Hour,
			MFAEnforcement:     "optional",
			Settings:           map[string]any{},
		})
	})

	// ---- Second tenant (Globex) so the workspace switcher shows more than one ----
	globex, err := tenantRepo.CreateWithOwner(ctx, tenant.CreateInput{Slug: "globex", Name: "Globex Corp", Plan: "free", Region: "eu-west-1"}, owner.ID)
	must(err, "create tenant globex")
	gMember, err := rbacSvc.CreateRole(ctx, globex.ID, "member", "Standard member", actor)
	must(err, "create globex member role")
	for _, p := range perms {
		if memberReads[p.Key] {
			must(rbacSvc.GrantPermission(ctx, gMember.ID, p.ID, actor), "grant globex member perm")
		}
	}
	erin, err := userRepo.CreateWithCredential(ctx, user.CreateInput{TenantID: globex.ID, Email: "erin@globex.test", DisplayName: "Erin Globex"}, pwHash)
	must(err, "create globex user")
	must(rbacSvc.AssignRole(ctx, erin.ID, globex.ID, gMember.ID, &owner.ID, actor), "assign globex member")

	// ---- A little login activity (sessions + login audit -> sessions page + analytics) ----
	for _, email := range []string{"owner@acme.test", "alice@acme.test", "bob@acme.test"} {
		for i := 0; i < 2; i++ {
			_, err := authSvc.Login(ctx, auth.LoginInput{Email: email, Password: seedPassword, IP: "203.0.113.10", UserAgent: "SeedScript/1.0"})
			must(err, "login "+email)
		}
	}

	fmt.Println("\n✅ Seed complete. Log in to the admin UI with any of:")
	fmt.Printf("   owner   owner@acme.test   %s   (owner of Acme + Globex)\n", seedPassword)
	fmt.Printf("   admin   alice@acme.test   %s\n", seedPassword)
	fmt.Printf("   member  bob@acme.test     %s\n", seedPassword)
	fmt.Println("   Tenants: Acme Inc (acme), Globex Corp (globex)")
	fmt.Printf("   Example OAuth clients: %s (Next.js), qci_example_spa (React SPA) — see frontend/examples/\n", exampleClientID)
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("seed: %s: %v", what, err)
	}
}

func ptr(s string) *string { return &s }
