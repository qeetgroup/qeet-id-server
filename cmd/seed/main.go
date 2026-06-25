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
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/policy"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id/domains/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id/domains/developer/agents"
	"github.com/qeetgroup/qeet-id/domains/developer/api-keys"
	"github.com/qeetgroup/qeet-id/domains/developer/auth-hooks"
	"github.com/qeetgroup/qeet-id/domains/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id/domains/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id/domains/developer/service-accounts"
	"github.com/qeetgroup/qeet-id/domains/developer/webhooks"
	"github.com/qeetgroup/qeet-id/domains/federation/ldap"
	"github.com/qeetgroup/qeet-id/domains/federation/scim"
	"github.com/qeetgroup/qeet-id/domains/federation/social"
	"github.com/qeetgroup/qeet-id/domains/identity/domains"
	"github.com/qeetgroup/qeet-id/domains/identity/groups"
	"github.com/qeetgroup/qeet-id/domains/identity/invitations"
	"github.com/qeetgroup/qeet-id/domains/identity/organizations"
	"github.com/qeetgroup/qeet-id/domains/identity/organizations/branding"
	"github.com/qeetgroup/qeet-id/domains/identity/users"
	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/domains/operations/billing"
	"github.com/qeetgroup/qeet-id/domains/operations/email-templates"
	"github.com/qeetgroup/qeet-id/domains/operations/notifications"
	"github.com/qeetgroup/qeet-id/domains/operations/retention"
	"github.com/qeetgroup/qeet-id/domains/operations/siem"
	"github.com/qeetgroup/qeet-id/platform/config"
	"github.com/qeetgroup/qeet-id/platform/database/postgres"
	"github.com/qeetgroup/qeet-id/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id/platform/security/encryption"
	"github.com/qeetgroup/qeet-id/platform/security/tokens"
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

	// Platform-wide billing plan catalog (free/starter/pro/enterprise + prices).
	// Idempotent; must exist before any tenant subscription is created.
	billingSvc := billing.NewService(pool)
	must(billingSvc.SeedBuiltins(ctx), "seed billing plans")

	// Services for the full-configuration coverage below. principal/agent/vc
	// reuse the issuer; ldap reuses authSvc; the secrets vault needs a data key.
	principalSvc := principal.NewService(pool, issuer)
	agentSvc := agent.NewService(pool, issuer)
	vcSvc := vc.NewService(pool, issuer)
	authhookSvc := authhook.NewService(pool)
	inviteSvc := invite.NewService(pool, notifier.LogSender{}, 14*24*time.Hour, cfg.AppBaseURL)
	domainSvc := domainverify.NewService(pool)
	emailTplSvc := emailtemplate.NewService(pool)
	retentionSvc := retention.NewService(pool)
	siemSvc := siem.NewService(pool)
	ipallowSvc := ipallow.NewService(pool)
	authPolicySvc := authpolicy.NewService(pool)
	notifySvc := notification.NewService(pool)
	ldapSvc := ldap.NewService(pool, authSvc)
	secretSvc, err := secret.NewService(ctx, pool, secretsKeyProvider(cfg))
	must(err, "init secrets vault")

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

	// ---- Demo enterprise / authz config (so the differentiator screens aren't empty) ----
	// ReBAC tuples for Access → Relationships. Group membership is modelled as
	// tuples too, so a userset resolves recursively: alice (∈ engineering) can
	// VIEW product-roadmap because engineering#member is a viewer; bob (∉ engineering)
	// cannot. Great for the explainable-authz "Access Tester" demo.
	rebacSvc := rebac.NewService(pool)
	demoTuples := []struct{ object, relation, subject string }{
		{"group:engineering", "member", "user:" + owner.ID.String()},
		{"group:engineering", "member", "user:" + users["alice@acme.test"].ID.String()},
		{"group:engineering", "member", "user:" + users["carol@acme.test"].ID.String()},
		{"document:product-roadmap", "owner", "user:" + owner.ID.String()},
		{"document:product-roadmap", "viewer", "group:engineering#member"},
		{"project:atlas", "editor", "user:" + users["alice@acme.test"].ID.String()},
		{"project:atlas", "viewer", "user:" + users["bob@acme.test"].ID.String()},
	}
	for _, t := range demoTuples {
		if _, e := rebacSvc.Write(ctx, acme.ID, t.object, t.relation, t.subject); e != nil {
			must(e, "rebac tuple "+t.object)
		}
	}
	fmt.Printf("  • rebac tuples  %d on Acme (Access → Relationships)\n", len(demoTuples))

	// A SCIM provisioning token so Auth → Connections → SCIM shows a configured directory.
	scimSvc := scim.NewService(pool, userRepo)
	var scimToken string
	inTx("scim token", func(tx pgx.Tx) error {
		t, e := scimSvc.Rotate(ctx, tx, acme.ID)
		scimToken = t
		return e
	})
	fmt.Printf("  • scim token    %s\n", scimToken)

	// A draft SAML connection so the "no SSO tax" SAML screens are populated. Read-only
	// in an offline demo — don't click "Test Connection" without a real IdP.
	_, err = pool.Exec(ctx, `
		INSERT INTO tenant.saml_connections
			(tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, name_attribute, status)
		SELECT $1, 'Acme Okta (demo)', 'https://acme.okta.com/exkdemo', 'https://acme.okta.com/app/demo/sso/saml',
			'-----BEGIN CERTIFICATE-----' || chr(10) || 'MIIDdemoPlaceholderNotARealCertForDisplayOnly' || chr(10) || '-----END CERTIFICATE-----',
			'email', 'displayName', 'draft'
		WHERE NOT EXISTS (
			SELECT 1 FROM tenant.saml_connections WHERE tenant_id = $1 AND name = 'Acme Okta (demo)'
		)
	`, acme.ID)
	must(err, "create demo saml connection")
	fmt.Println("  • saml conn     \"Acme Okta (demo)\" (draft) on Acme")

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

	// ════════════════════════════════════════════════════════════════════════
	//  Full configuration coverage on Acme — one realistic example per admin
	//  screen so nothing has to be set up by hand. All values are fake/dev-only.
	// ════════════════════════════════════════════════════════════════════════

	// ---- Auth policy (login methods + password rules) ----
	inTx("auth policy", func(tx pgx.Tx) error {
		_, e := authPolicySvc.Update(ctx, tx, acme.ID, authpolicy.Policy{
			PasswordEnabled:          true,
			PasswordMinLength:        10,
			PasswordRequireUppercase: true,
			PasswordRequireNumber:    true,
			MagicLinkEnabled:         true,
			MagicLinkTTLMinutes:      30,
			PasskeyEnabled:           true,
			OTPEmailEnabled:          true,
		})
		return e
	})

	// ---- IP allow/deny rules ----
	inTx("ip rules", func(tx pgx.Tx) error {
		if _, e := ipallowSvc.AddRule(ctx, tx, acme.ID, "203.0.113.0/24", "Office network", "allow"); e != nil {
			return e
		}
		_, e := ipallowSvc.AddRule(ctx, tx, acme.ID, "198.51.100.7/32", "Known bad actor", "deny")
		return e
	})

	// ---- Billing subscription (Acme → Pro). Catalog seeded above. ----
	inTx("acme subscription", func(tx pgx.Tx) error {
		_, e := billingSvc.ChangePlan(ctx, tx, acme.ID, "pro", "USD")
		return e
	})

	// ---- Service account (M2M) — secret shown once. ----
	var saSecret string
	inTx("service account", func(tx pgx.Tx) error {
		_, sec, e := principalSvc.Create(ctx, tx, principal.CreateInput{
			TenantID: acme.ID, Name: "Backend API", Description: "Server-to-server access",
			Scopes: []string{"users:read", "audit:read"},
		})
		saSecret = sec
		return e
	})
	fmt.Printf("  • service acct  %-14q %s\n", "Backend API", saSecret)

	// ---- Secrets vault ----
	_, err = secretSvc.Create(ctx, acme.ID, "STRIPE_API_KEY", "billing", "sk_test_demo_0123456789abcdef")
	must(err, "vault STRIPE_API_KEY")
	_, err = secretSvc.Create(ctx, acme.ID, "SENDGRID_API_KEY", "email", "SG.demo.0123456789abcdef")
	must(err, "vault SENDGRID_API_KEY")
	fmt.Println("  • vault secrets STRIPE_API_KEY, SENDGRID_API_KEY")

	// ---- Auth hook (post-login policy webhook) ----
	_, err = authhookSvc.Create(ctx, acme.ID, "https://hooks.acme.test/auth", "whsec_demo_authhook", true)
	must(err, "auth hook")

	// ---- AI agent (ephemeral scoped tokens) ----
	_, err = agentSvc.Create(ctx, acme.ID, "Support Copilot", []string{"users:read"}, 3600)
	must(err, "ai agent")

	// ---- Verifiable credential issued to the owner ----
	_, err = vcSvc.Issue(ctx, acme.ID, "user:"+owner.ID.String(), "EmployeeCredential",
		map[string]any{"name": "Olivia Owner", "title": "Founder", "tenant": "Acme Inc"}, 365*24*3600)
	must(err, "verifiable credential")

	// ---- Pending invitation ----
	_, inviteToken, err := inviteSvc.Create(ctx, invite.CreateInput{TenantID: acme.ID, Email: "frank@acme.test", RoleID: &memberRole.ID}, &owner.ID)
	must(err, "invitation")
	fmt.Printf("  • invitation    frank@acme.test (token: %s)\n", inviteToken)

	// ---- Domain verification (pending DNS TXT) ----
	_, err = domainSvc.Add(ctx, acme.ID, "acme.test")
	must(err, "domain verification")

	// ---- Email template override ----
	inTx("email template", func(tx pgx.Tx) error {
		_, e := emailTplSvc.Upsert(ctx, tx, acme.ID, "verify_email",
			"Verify your Acme account", "Welcome to Acme! Your verification code is {{code}} (expires in {{ttl}}).")
		return e
	})

	// ---- Data-retention policy (purge soft-deleted users after 30 days) ----
	inTx("retention policy", func(tx pgx.Tx) error {
		_, e := retentionSvc.Update(ctx, tx, acme.ID, retention.Policy{DeletedUsersEnabled: true, DeletedUsersDays: 30})
		return e
	})

	// ---- SIEM log sink ----
	_, err = siemSvc.Create(ctx, acme.ID, "datadog", "https://http-intake.logs.datadoghq.com/api/v2/logs", "dd-demo-token")
	must(err, "siem sink")

	// ---- In-app notifications for the owner ----
	must(notifySvc.Notify(ctx, acme.ID, owner.ID, "info", "Welcome to Qeet ID", "Your workspace is ready. Invite your team to get started.", "/users"), "notify welcome")
	must(notifySvc.Notify(ctx, acme.ID, owner.ID, "alert", "New sign-in", "A new sign-in to your account was detected from 203.0.113.10.", "/security"), "notify signin")

	// ---- LDAP / Active Directory connection (draft) ----
	inTx("ldap connection", func(tx pgx.Tx) error {
		_, e := ldapSvc.Create(ctx, tx, acme.ID, ldap.CreateInput{
			Name: "Acme AD (demo)", ServerURL: "ldaps://ad.acme.test:636", StartTLS: false,
			BindDN: "CN=svc-qeet,OU=Service,DC=acme,DC=test", BindPassword: "demo-bind-password",
			BaseDN: "OU=Users,DC=acme,DC=test", UserFilter: "(sAMAccountName=%s)",
			EmailAttribute: "mail", NameAttribute: "displayName", Status: "draft",
		})
		return e
	})

	// ---- SAML IdP-side service provider (Qeet as IdP, draft). Inserted directly
	// to avoid building an IdP signer just for a display row (see cmd/server). ----
	_, err = pool.Exec(ctx, `
		INSERT INTO tenant.saml_service_providers
			(tenant_id, name, entity_id, acs_url, name_id_format, name_id_attribute, certificate, status)
		SELECT $1, 'Acme Internal Wiki (demo)', 'https://wiki.acme.test/saml/metadata',
			'https://wiki.acme.test/saml/acs', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
			'email', '', 'draft'
		WHERE NOT EXISTS (
			SELECT 1 FROM tenant.saml_service_providers WHERE tenant_id = $1 AND entity_id = 'https://wiki.acme.test/saml/metadata'
		)
	`, acme.ID)
	must(err, "saml service provider")
	fmt.Println("  • saml SP       \"Acme Internal Wiki (demo)\" (draft, IdP-side) on Acme")

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
	inTx("globex subscription", func(tx pgx.Tx) error {
		_, e := billingSvc.ChangePlan(ctx, tx, globex.ID, "free", "USD")
		return e
	})

	// ---- A little login activity (sessions + login audit -> sessions page + analytics) ----
	for _, email := range []string{"owner@acme.test", "alice@acme.test", "bob@acme.test", "carol@acme.test", "dave@acme.test"} {
		for i := 0; i < 2; i++ {
			_, err := authSvc.Login(ctx, auth.LoginInput{Email: email, Password: seedPassword, IP: "203.0.113.10", UserAgent: "SeedScript/1.0"})
			must(err, "login "+email)
		}
	}

	fmt.Println("\n✅ Seed complete. Log in to the admin UI with any of:")
	fmt.Printf("   owner   owner@acme.test   %s   (owner of Acme + Globex)\n", seedPassword)
	fmt.Printf("   admin   alice@acme.test   %s\n", seedPassword)
	fmt.Printf("   member  bob@acme.test     %s\n", seedPassword)
	fmt.Println("   Tenants: Acme Inc (acme, Pro), Globex Corp (globex, Free)")
	fmt.Printf("   Example OAuth clients: %s (Next.js), qci_example_spa (React SPA) — see frontend/examples/\n", exampleClientID)
	fmt.Println("   Acme is fully configured: billing, service accounts, secrets vault, auth hooks,")
	fmt.Println("   AI agents, verifiable credentials, invitations, domains, email templates, retention,")
	fmt.Println("   SIEM, IP rules, auth policy, notifications, LDAP & SAML — every screen has data.")
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("seed: %s: %v", what, err)
	}
}

func ptr(s string) *string { return &s }

// secretsKeyProvider mirrors cmd/server: decode SECRETS_KEY (base64) for the
// vault's AES data key, or generate an ephemeral key in dev when it's unset
// (stored secrets then won't survive a restart — fine for seed data).
func secretsKeyProvider(cfg *config.Config) secret.KeyProvider {
	if cfg.SecretsKey != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.SecretsKey)
		must(err, "decode SECRETS_KEY")
		return secret.StaticKeyProvider{Key: key}
	}
	key := make([]byte, 32)
	_, err := rand.Read(key)
	must(err, "generate ephemeral secrets key")
	return secret.StaticKeyProvider{Key: key}
}
