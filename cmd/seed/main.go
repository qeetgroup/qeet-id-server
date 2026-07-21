// Command seed populates the database with a realistic, production-shaped set of
// workspaces so the admin UI has data to browse. It uses the app's own
// services/repositories, so passwords are real bcrypt (you can log in), users
// appear via rbac membership, and audit rows are properly hash-chained.
//
//	make seed          # seed on top of whatever exists
//	make seed-reset    # wipe (dev only) then seed a clean dataset
//
// The dataset models Qeet Group dogfooding its own identity platform (the one
// genuinely-real org — the fully-configured primary workspace on qeet.in)
// alongside a set of *fictional* customer organizations at production-like
// scale: believable company/person names on realistic domains, dozens of users,
// multiple groups, varied plans/regions/currencies, and login history. It is not
// real customer data — Qeet has no real tenants yet; this is demo data that
// simply reads like production. The seed's notifier only logs, so no mail is
// ever sent. Everyone shares the dev password below.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/policy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/developer/agents"
	"github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	"github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/branding"
	"github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/email"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notifications"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

const seedPassword = "Password123!"

// Name pools for generating believable, ASCII-only people (Indian + international,
// matching Qeet's India-first-but-global posture). The lengths are coprime (31, 29)
// so walking a single incrementing index yields unique (first, last) pairs — and
// therefore globally-unique emails — for the first 31*29 = 899 users.
var (
	firstNames = []string{
		"Aarav", "Priya", "Rohan", "Ananya", "Vikram", "Sneha", "Kabir", "Diya",
		"Arjun", "Isha", "Rahul", "Meera", "Karan", "Nisha", "Aditya", "Pooja",
		"Rohit", "Kavya", "Siddharth", "Tara", "Emily", "Daniel", "Sofia", "Noah",
		"Grace", "Liam", "Olivia", "Mateo", "Hannah", "Lucas", "Ravi",
	}
	lastNames = []string{
		"Mehta", "Nair", "Gupta", "Iyer", "Reddy", "Kulkarni", "Shah", "Desai",
		"Rao", "Kapoor", "Sharma", "Menon", "Bose", "Chopra", "Pillai", "Verma",
		"Sinha", "Joshi", "Nanda", "Bhat", "Carter", "Brooks", "Rossi", "Andersson",
		"Okafor", "Nguyen", "Silva", "Sheikh", "Larsson",
	}
)

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
	emailTplSvc := email.NewService(pool)
	retentionSvc := retention.NewService(pool)
	siemSvc := siem.NewService(pool)
	ipallowSvc := ipallow.NewService(pool)
	authPolicySvc := authpolicy.NewService(pool)
	notifySvc := notification.NewService(pool)
	ldapSvc := ldap.NewService(pool, authSvc)
	rebacSvc := rebac.NewService(pool)
	scimSvc := scim.NewService(pool, userRepo)
	secretSvc, err := secret.NewService(ctx, pool, secretsKeyProvider(cfg))
	must(err, "init secrets vault")

	pwHash, err := password.Hash(seedPassword)
	must(err, "hash password")

	// Platform-wide permission catalog (permissions are global builtins), fetched
	// once and reused to grant roles across every tenant below.
	perms, err := rbacRepo.ListPermissions(ctx)
	must(err, "list permissions")
	// member is read-only: the four basic browse permissions only — nothing
	// sensitive (no audit/secrets/keys/connections/billing) and no writes.
	memberReads := map[string]bool{"tenant.read": true, "user.read": true, "role.read": true, "group.read": true}
	grantAll := func(roleID uuid.UUID, a audit.Actor) {
		for _, p := range perms {
			must(rbacSvc.GrantPermission(ctx, roleID, p.ID, a), "grant perm")
		}
	}
	grantReads := func(roleID uuid.UUID, keys map[string]bool, a audit.Actor) {
		for _, p := range perms {
			if keys[p.Key] {
				must(rbacSvc.GrantPermission(ctx, roleID, p.ID, a), "grant read perm")
			}
		}
	}

	// genUser mints the next unique (name, email@domain) from the pools above.
	nameIdx := 0
	genUser := func(domain string) (email, name string) {
		f := firstNames[nameIdx%len(firstNames)]
		l := lastNames[nameIdx%len(lastNames)]
		nameIdx++
		return strings.ToLower(f) + "." + strings.ToLower(l) + "@" + domain, f + " " + l
	}

	// logins accumulates a sample of loginable emails so we can generate realistic
	// session/audit/analytics history at the end.
	var logins []string

	// ════════════════════════════════════════════════════════════════════════
	//  Primary workspace — Qeet Group dogfooding Qeet ID (qeet.in, Enterprise).
	//  The one genuinely-real org. Fully configured: every admin screen has data
	//  so nothing has to be set up by hand. An identity vendor legitimately wires
	//  up every connection type (SAML, LDAP, SCIM, social) against test IdPs.
	// ════════════════════════════════════════════════════════════════════════

	// Signup creates a tenant-less identity; CreateWithOwner then makes them the
	// owner of Qeet Group (owner role + membership + home tenant).
	_, founder, _, err := authSvc.Signup(ctx, auth.SignupInput{Email: "saibabu@qeet.in", Password: seedPassword, DisplayName: "Mareedu Saibabu"})
	must(err, "signup founder")
	qeet, err := tenantRepo.CreateWithOwner(ctx, tenant.CreateInput{Slug: "qeet", Name: "Qeet Group", Plan: "enterprise", Region: "ap-south-1"}, founder.ID)
	must(err, "create tenant qeet")
	actor := audit.Actor{UserID: &founder.ID, Type: "user"}
	logins = append(logins, "saibabu@qeet.in")

	// ---- Roles in Qeet Group (admin / engineer / member) ----
	adminRole, err := rbacSvc.CreateRole(ctx, qeet.ID, "admin", "Full administrative access", actor)
	must(err, "create admin role")
	grantAll(adminRole.ID, actor)
	engineerRole, err := rbacSvc.CreateRole(ctx, qeet.ID, "engineer", "Read all + manage users, groups, keys, webhooks & connections", actor)
	must(err, "create engineer role")
	engineerPerms := map[string]bool{
		"tenant.read": true, "user.read": true, "user.write": true, "role.read": true,
		"group.read": true, "group.write": true, "audit.read": true, "analytics.read": true,
		"connection.read": true, "apikey.read": true, "apikey.write": true,
		"webhook.read": true, "webhook.write": true, "policy.read": true,
	}
	grantReads(engineerRole.ID, engineerPerms, actor)
	memberRole, err := rbacSvc.CreateRole(ctx, qeet.ID, "member", "Standard member (read-only)", actor)
	must(err, "create member role")
	grantReads(memberRole.ID, memberReads, actor)

	// ---- Named leadership (stable emails referenced by groups/rebac/config below) ----
	leadership := []struct {
		email, name string
		role        uuid.UUID
	}{
		{"aarav@qeet.in", "Aarav Mehta", adminRole.ID},        // VP Engineering
		{"priya@qeet.in", "Priya Nair", adminRole.ID},         // Head of Security
		{"tara@qeet.in", "Tara Menon", adminRole.ID},          // Head of Product
		{"vikram@qeet.in", "Vikram Reddy", adminRole.ID},      // Head of Operations
		{"rohan@qeet.in", "Rohan Gupta", engineerRole.ID},     // Staff Engineer
		{"diego@qeet.in", "Diego Fernandez", engineerRole.ID}, // Senior Engineer
		{"ananya@qeet.in", "Ananya Iyer", engineerRole.ID},    // Product Engineer
		{"sneha@qeet.in", "Sneha Kulkarni", memberRole.ID},    // Support Lead
		{"grace@qeet.in", "Grace Okafor", memberRole.ID},      // Developer Advocate
	}
	staff := map[string]*user.User{}
	for _, m := range leadership {
		u, err := userRepo.CreateWithCredential(ctx, user.CreateInput{TenantID: qeet.ID, Email: m.email, DisplayName: m.name}, pwHash)
		must(err, "create user "+m.email)
		must(rbacSvc.AssignRole(ctx, u.ID, qeet.ID, m.role, &founder.ID, actor), "assign role "+m.email)
		staff[m.email] = u
	}
	logins = append(logins, "aarav@qeet.in", "priya@qeet.in", "rohan@qeet.in", "sneha@qeet.in")

	// ---- Groups ----
	mkGroup := func(name, desc string) uuid.UUID {
		g, err := groupSvc.Create(ctx, group.CreateInput{TenantID: qeet.ID, Name: name, Description: desc}, actor)
		must(err, "create group "+name)
		return g.ID
	}
	engGroup := mkGroup("Engineering", "Platform & product engineering")
	secGroup := mkGroup("Security", "Security & compliance")
	prodGroup := mkGroup("Product", "Product management")
	designGroup := mkGroup("Design", "Product design")
	supGroup := mkGroup("Support", "Customer support")
	devrelGroup := mkGroup("Developer Relations", "DevRel & documentation")
	salesGroup := mkGroup("Sales", "Revenue & partnerships")
	qeetGroups := []uuid.UUID{engGroup, secGroup, prodGroup, designGroup, supGroup, devrelGroup, salesGroup}

	seedGroupMember := func(g, u uuid.UUID) { must(groupSvc.AddMember(ctx, g, u, qeet.ID, actor), "group add member") }
	seedGroupMember(engGroup, founder.ID)
	seedGroupMember(engGroup, staff["aarav@qeet.in"].ID)
	seedGroupMember(engGroup, staff["rohan@qeet.in"].ID)
	seedGroupMember(engGroup, staff["diego@qeet.in"].ID)
	seedGroupMember(engGroup, staff["ananya@qeet.in"].ID)
	seedGroupMember(secGroup, founder.ID)
	seedGroupMember(secGroup, staff["priya@qeet.in"].ID)
	seedGroupMember(prodGroup, staff["tara@qeet.in"].ID)
	seedGroupMember(supGroup, staff["sneha@qeet.in"].ID)
	seedGroupMember(devrelGroup, staff["grace@qeet.in"].ID)
	seedGroupMember(salesGroup, staff["vikram@qeet.in"].ID)

	// ---- Bulk staff so the roster reads like a real ~20-person company ----
	bulkRoles := []uuid.UUID{engineerRole.ID, engineerRole.ID, memberRole.ID}
	for i := 0; i < 11; i++ {
		email, name := genUser("qeet.in")
		u, err := userRepo.CreateWithCredential(ctx, user.CreateInput{TenantID: qeet.ID, Email: email, DisplayName: name}, pwHash)
		must(err, "create staff "+email)
		must(rbacSvc.AssignRole(ctx, u.ID, qeet.ID, bulkRoles[i%len(bulkRoles)], &founder.ID, actor), "assign staff "+email)
		seedGroupMember(qeetGroups[i%len(qeetGroups)], u.ID)
		if i%4 == 0 {
			logins = append(logins, email)
		}
	}

	// ---- API keys ----
	for _, name := range []string{"Production API", "GitHub Actions CI", "qeet-logs ingestion"} {
		k, full, err := apikeySvc.Create(ctx, apikey.CreateInput{TenantID: qeet.ID, UserID: &founder.ID, Name: name, Scopes: []string{"users:read", "audit:read"}})
		must(err, "create api key "+name)
		fmt.Printf("  • api key %-22q %s\n", k.Name, full)
	}

	// ---- Demo OIDC client for the Next.js example app (examples/nextjs-app) ----
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
	`, qeet.ID, exampleClientID, exHash,
		[]string{"http://localhost:3010/api/auth/callback"},
		[]string{"http://localhost:3010", "http://localhost:3010/"})
	must(err, "create example oidc client")
	fmt.Printf("  • oidc client  %-22q %s (secret: %s)\n", "Example Web App", exampleClientID, exampleClientSecret)

	// A PUBLIC client (no secret) for the React SPA example (examples/react-app),
	// which runs the Authorization-Code + PKCE flow entirely in the browser. The SPA's
	// origin must also be in ALLOWED_ORIGINS for the cross-origin token/userinfo calls.
	_, err = pool.Exec(ctx, `
		INSERT INTO auth.oidc_clients (
			tenant_id, client_id, client_secret_hash, type, name,
			redirect_uris, post_logout_uris, grant_types, scopes
		) VALUES ($1, $2, NULL, 'public', 'Example SPA (React)',
			$3, $4, '{authorization_code}', '{openid,profile,email}')
		ON CONFLICT (client_id) DO NOTHING
	`, qeet.ID, "qci_example_spa",
		[]string{"http://localhost:3020/callback"},
		[]string{"http://localhost:3020", "http://localhost:3020/"})
	must(err, "create example spa oidc client")
	fmt.Printf("  • oidc client  %-22q %s (public, PKCE — no secret)\n", "Example SPA", "qci_example_spa")

	// ---- ReBAC tuples (Access → Relationships) ----
	// Group membership is modelled as tuples too, so a userset resolves recursively:
	// rohan (∈ engineering) can VIEW the security runbook because engineering#member
	// is a viewer; sneha (∉ engineering) cannot. Great for the explainable-authz
	// "Access Tester" demo.
	demoTuples := []struct{ object, relation, subject string }{
		{"group:engineering", "member", "user:" + founder.ID.String()},
		{"group:engineering", "member", "user:" + staff["aarav@qeet.in"].ID.String()},
		{"group:engineering", "member", "user:" + staff["rohan@qeet.in"].ID.String()},
		{"group:engineering", "member", "user:" + staff["diego@qeet.in"].ID.String()},
		{"document:security-runbook", "owner", "user:" + staff["priya@qeet.in"].ID.String()},
		{"document:security-runbook", "viewer", "group:engineering#member"},
		{"project:qeet-pay-launch", "editor", "user:" + staff["rohan@qeet.in"].ID.String()},
		{"project:qeet-pay-launch", "viewer", "user:" + staff["sneha@qeet.in"].ID.String()},
	}
	for _, t := range demoTuples {
		if _, e := rebacSvc.Write(ctx, qeet.ID, t.object, t.relation, t.subject); e != nil {
			must(e, "rebac tuple "+t.object)
		}
	}
	fmt.Printf("  • rebac tuples  %d on Qeet Group (Access → Relationships)\n", len(demoTuples))

	// A SCIM provisioning token so Auth → Connections → SCIM shows a configured directory.
	var scimToken string
	inTx("scim token", func(tx pgx.Tx) error {
		t, e := scimSvc.Rotate(ctx, tx, qeet.ID)
		scimToken = t
		return e
	})
	fmt.Printf("  • scim token    %s\n", scimToken)

	// A draft SAML connection (Google Workspace as staff IdP) so the "no SSO tax"
	// SAML screens are populated. Read-only in an offline demo — don't click
	// "Test Connection" without a real IdP.
	_, err = pool.Exec(ctx, `
		INSERT INTO tenant.saml_connections
			(tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, name_attribute, status)
		SELECT $1, 'Qeet Google Workspace', 'https://accounts.google.com/o/saml2?idpid=C0qeetsso',
			'https://accounts.google.com/o/saml2/idp?idpid=C0qeetsso',
			'-----BEGIN CERTIFICATE-----' || chr(10) || 'MIIDdemoPlaceholderNotARealCertForDisplayOnly' || chr(10) || '-----END CERTIFICATE-----',
			'email', 'displayName', 'draft'
		WHERE NOT EXISTS (
			SELECT 1 FROM tenant.saml_connections WHERE tenant_id = $1 AND name = 'Qeet Google Workspace'
		)
	`, qeet.ID)
	must(err, "create demo saml connection")
	fmt.Println("  • saml conn     \"Qeet Google Workspace\" (draft) on Qeet Group")

	// ---- Webhooks (Qeet Notify consumes identity events; audit stream sink) ----
	inTx("webhook 1", func(tx pgx.Tx) error {
		_, e := webhookSvc.Create(ctx, tx, webhook.CreateInput{TenantID: qeet.ID, URL: "https://api.notify.qeet.in/v1/webhooks/qeet-id", Events: []string{"user.created", "auth.login_succeeded", "user.deleted"}})
		return e
	})
	inTx("webhook 2", func(tx pgx.Tx) error {
		_, e := webhookSvc.Create(ctx, tx, webhook.CreateInput{TenantID: qeet.ID, URL: "https://hooks.qeet.in/audit-stream", Events: []string{}})
		return e
	})

	// ---- Social providers ----
	_, err = socialSvc.UpsertProvider(ctx, social.CreateProviderInput{TenantID: qeet.ID, Provider: "google", ClientID: "google-client-id", ClientSecret: "google-secret", DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration"})
	must(err, "social google")
	_, err = socialSvc.UpsertProvider(ctx, social.CreateProviderInput{TenantID: qeet.ID, Provider: "github", ClientID: "github-client-id", ClientSecret: "github-secret"})
	must(err, "social github")

	// ---- Branding (Qeet orange) + baseline policy ----
	inTx("branding", func(tx pgx.Tx) error {
		return brandingRepo.Upsert(ctx, tx, branding.Branding{
			TenantID:         qeet.ID,
			PrimaryColor:     ptr("#F26D0E"),
			SecondaryColor:   ptr("#D85301"),
			EmailFromName:    ptr("Qeet Security"),
			EmailFromAddress: ptr("security@qeet.in"),
			Settings:         map[string]any{"login_headline": "Sign in to Qeet"},
		})
	})
	inTx("policy", func(tx pgx.Tx) error {
		return policyRepo.Upsert(ctx, tx, policy.Policy{
			TenantID:           qeet.ID,
			IPAllowlist:        []string{},
			IPDenylist:         []string{},
			PasswordMinLength:  12,
			PasswordComplexity: "standard",
			SessionMaxAge:      12 * time.Hour,
			MFAEnforcement:     "required",
			Settings:           map[string]any{},
		})
	})

	// ---- Auth policy (passkeys-first, MFA enforced) ----
	inTx("auth policy", func(tx pgx.Tx) error {
		_, e := authPolicySvc.Update(ctx, tx, qeet.ID, authpolicy.Policy{
			PasswordEnabled:          true,
			PasswordMinLength:        12,
			PasswordRequireUppercase: true,
			PasswordRequireNumber:    true,
			MagicLinkEnabled:         true,
			MagicLinkTTLMinutes:      30,
			PasskeyEnabled:           true,
			OTPEmailEnabled:          true,
		})
		return e
	})

	// ---- IP allow/deny rules (TEST-NET documentation ranges — never route) ----
	inTx("ip rules", func(tx pgx.Tx) error {
		if _, e := ipallowSvc.AddRule(ctx, tx, qeet.ID, "203.0.113.0/24", "Bengaluru HQ", "allow"); e != nil {
			return e
		}
		_, e := ipallowSvc.AddRule(ctx, tx, qeet.ID, "198.51.100.23/32", "Blocked host", "deny")
		return e
	})

	// ---- Billing subscription (Qeet Group → Enterprise, INR). Catalog seeded above. ----
	inTx("qeet subscription", func(tx pgx.Tx) error {
		_, e := billingSvc.ChangePlan(ctx, tx, qeet.ID, "enterprise", "INR")
		return e
	})

	// ---- Service account (M2M) — secret shown once. ----
	var saSecret string
	inTx("service account", func(tx pgx.Tx) error {
		_, sec, e := principalSvc.Create(ctx, tx, principal.CreateInput{
			TenantID: qeet.ID, Name: "Platform automation", Description: "Server-to-server access for internal tooling",
			Scopes: []string{"users:read", "audit:read"},
		})
		saSecret = sec
		return e
	})
	fmt.Printf("  • service acct  %-22q %s\n", "Platform automation", saSecret)

	// ---- Secrets vault (India/AWS-flavoured; placeholder values, dev-only) ----
	_, err = secretSvc.Create(ctx, qeet.ID, "RAZORPAY_KEY_SECRET", "billing", "rzp_test_seedPlaceholder0123456789")
	must(err, "vault RAZORPAY_KEY_SECRET")
	_, err = secretSvc.Create(ctx, qeet.ID, "AWS_SES_SMTP_PASSWORD", "email", "BSeedPlaceholderSmtpPassword0123456789ab")
	must(err, "vault AWS_SES_SMTP_PASSWORD")
	fmt.Println("  • vault secrets RAZORPAY_KEY_SECRET, AWS_SES_SMTP_PASSWORD")

	// ---- Auth hook (post-login risk policy webhook) ----
	_, err = authhookSvc.Create(ctx, qeet.ID, "https://api.id.qeet.in/internal/hooks/risk", "whsec_seed_placeholder_authhook", true)
	must(err, "auth hook")

	// ---- AI agent (ephemeral scoped tokens) ----
	_, err = agentSvc.Create(ctx, qeet.ID, "Support Copilot", []string{"users:read"}, 3600, founder.ID)
	must(err, "ai agent")

	// ---- Verifiable credential issued to the founder ----
	_, err = vcSvc.Issue(ctx, qeet.ID, "user:"+founder.ID.String(), "EmployeeCredential",
		map[string]any{"name": "Mareedu Saibabu", "title": "Founder & CEO", "org": "Qeet Group"}, 365*24*3600)
	must(err, "verifiable credential")

	// ---- Pending invitation (new hire) ----
	_, inviteToken, err := inviteSvc.Create(ctx, invite.CreateInput{TenantID: qeet.ID, Email: "kabir@qeet.in", RoleID: &memberRole.ID}, &founder.ID)
	must(err, "invitation")
	fmt.Printf("  • invitation    kabir@qeet.in (token: %s)\n", inviteToken)

	// ---- Domain verification (pending DNS TXT for qeet.in) ----
	_, err = domainSvc.Add(ctx, qeet.ID, "qeet.in")
	must(err, "domain verification")

	// ---- Email template override ----
	inTx("email template", func(tx pgx.Tx) error {
		_, e := emailTplSvc.Upsert(ctx, tx, qeet.ID, "verify_email",
			"Verify your Qeet account", "Welcome to Qeet! Your verification code is {{code}} (expires in {{ttl}}).")
		return e
	})

	// ---- Data-retention policy (purge soft-deleted users after 30 days) ----
	inTx("retention policy", func(tx pgx.Tx) error {
		_, e := retentionSvc.Update(ctx, tx, qeet.ID, retention.Policy{DeletedUsersEnabled: true, DeletedUsersDays: 30})
		return e
	})

	// ---- SIEM log sink ----
	_, err = siemSvc.Create(ctx, qeet.ID, "datadog", "https://http-intake.logs.datadoghq.com/api/v2/logs", "dd_seed_placeholder_token")
	must(err, "siem sink")

	// ---- In-app notifications for the founder ----
	must(notifySvc.Notify(ctx, qeet.ID, founder.ID, "info", "Welcome to Qeet ID", "Your Qeet Group workspace is ready. Invite the rest of the team to get started.", "/users"), "notify welcome")
	must(notifySvc.Notify(ctx, qeet.ID, founder.ID, "alert", "New sign-in", "A new sign-in to your account was detected from 203.0.113.10 (Bengaluru).", "/security"), "notify signin")

	// ---- LDAP connection (draft) — dogfood test directory. ----
	inTx("ldap connection", func(tx pgx.Tx) error {
		_, e := ldapSvc.Create(ctx, tx, qeet.ID, ldap.CreateInput{
			Name: "Staging Directory (test)", ServerURL: "ldaps://ldap.staging.qeet.in:636", StartTLS: false,
			BindDN: "cn=svc-qeet-id,ou=service,dc=staging,dc=qeet,dc=in", BindPassword: "seed-placeholder-bind-password",
			BaseDN: "ou=people,dc=staging,dc=qeet,dc=in", UserFilter: "(uid=%s)",
			EmailAttribute: "mail", NameAttribute: "displayName", Status: "draft",
		})
		return e
	})

	// ---- SAML IdP-side service provider (Qeet as IdP, draft). Inserted directly
	// to avoid building an IdP signer just for a display row (see cmd/server). ----
	_, err = pool.Exec(ctx, `
		INSERT INTO tenant.saml_service_providers
			(tenant_id, name, entity_id, acs_url, name_id_format, name_id_attribute, certificate, status)
		SELECT $1, 'Qeet Internal Wiki', 'https://wiki.qeet.in/saml/metadata',
			'https://wiki.qeet.in/saml/acs', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
			'email', '', 'draft'
		WHERE NOT EXISTS (
			SELECT 1 FROM tenant.saml_service_providers WHERE tenant_id = $1 AND entity_id = 'https://wiki.qeet.in/saml/metadata'
		)
	`, qeet.ID)
	must(err, "saml service provider")
	fmt.Println("  • saml SP       \"Qeet Internal Wiki\" (draft, IdP-side) on Qeet Group")

	// ---- Qeet Sandbox — the founder's second, internal workspace (Free). Gives
	//      the primary login a second workspace so the switcher isn't a single
	//      entry, without mixing staff into customer orgs. ----
	sandbox, err := tenantRepo.CreateWithOwner(ctx, tenant.CreateInput{Slug: "qeet-sandbox", Name: "Qeet Sandbox", Plan: "free", Region: "ap-south-1"}, founder.ID)
	must(err, "create tenant sandbox")
	sbMember, err := rbacSvc.CreateRole(ctx, sandbox.ID, "member", "Standard member (read-only)", actor)
	must(err, "create sandbox member role")
	grantReads(sbMember.ID, memberReads, actor)
	qa, err := userRepo.CreateWithCredential(ctx, user.CreateInput{TenantID: sandbox.ID, Email: "qa@qeet.in", DisplayName: "QA Bot"}, pwHash)
	must(err, "create sandbox user")
	must(rbacSvc.AssignRole(ctx, qa.ID, sandbox.ID, sbMember.ID, &founder.ID, actor), "assign sandbox member")
	inTx("sandbox subscription", func(tx pgx.Tx) error {
		_, e := billingSvc.ChangePlan(ctx, tx, sandbox.ID, "free", "INR")
		return e
	})

	// ════════════════════════════════════════════════════════════════════════
	//  Customer workspaces — fictional orgs on realistic domains, at scale. Each
	//  is owned by its own admin (proper tenant isolation), with a generated
	//  roster, groups, and a plan-appropriate SSO/social connection. Names and
	//  domains are invented; any resemblance to a real company is coincidental.
	// ════════════════════════════════════════════════════════════════════════

	type orgInput struct {
		slug, name, domain, plan, region, currency string
		users                                      int // non-owner members
		groups                                     []string
	}
	// seedOrg provisions a customer workspace: a fresh, loginable owner (via
	// Signup → CreateWithOwner), admin+member roles, `users` generated teammates
	// (every 6th an admin) each assigned a role and slotted into a group, and a
	// billing subscription. Returns the tenant + owner for per-org extras.
	seedOrg := func(o orgInput) (*tenant.Tenant, *user.User) {
		ownerEmail, ownerName := genUser(o.domain)
		_, orgOwner, _, err := authSvc.Signup(ctx, auth.SignupInput{Email: ownerEmail, Password: seedPassword, DisplayName: ownerName})
		must(err, "signup owner "+ownerEmail)
		t, err := tenantRepo.CreateWithOwner(ctx, tenant.CreateInput{Slug: o.slug, Name: o.name, Plan: o.plan, Region: o.region}, orgOwner.ID)
		must(err, "create tenant "+o.slug)
		a := audit.Actor{UserID: &orgOwner.ID, Type: "user"}
		orgAdmin, err := rbacSvc.CreateRole(ctx, t.ID, "admin", "Full administrative access", a)
		must(err, "admin role "+o.slug)
		grantAll(orgAdmin.ID, a)
		orgMember, err := rbacSvc.CreateRole(ctx, t.ID, "member", "Standard member (read-only)", a)
		must(err, "member role "+o.slug)
		grantReads(orgMember.ID, memberReads, a)
		var orgGroups []uuid.UUID
		for _, gname := range o.groups {
			g, err := groupSvc.Create(ctx, group.CreateInput{TenantID: t.ID, Name: gname}, a)
			must(err, "group "+gname)
			orgGroups = append(orgGroups, g.ID)
		}
		for i := 0; i < o.users; i++ {
			email, name := genUser(o.domain)
			cu, err := userRepo.CreateWithCredential(ctx, user.CreateInput{TenantID: t.ID, Email: email, DisplayName: name}, pwHash)
			must(err, "create user "+email)
			role := orgMember.ID
			if i%6 == 0 {
				role = orgAdmin.ID
			}
			must(rbacSvc.AssignRole(ctx, cu.ID, t.ID, role, &orgOwner.ID, a), "assign "+email)
			if len(orgGroups) > 0 {
				must(groupSvc.AddMember(ctx, orgGroups[i%len(orgGroups)], cu.ID, t.ID, a), "group add "+email)
			}
		}
		inTx("subscription "+o.slug, func(tx pgx.Tx) error {
			_, e := billingSvc.ChangePlan(ctx, tx, t.ID, o.plan, o.currency)
			return e
		})
		logins = append(logins, orgOwner.Email)
		return t, orgOwner
	}

	// A draft Okta SAML connection — enterprises expect "no SSO tax".
	addSAML := func(tenantID uuid.UUID, connName, oktaSub string) {
		_, err := pool.Exec(ctx, `
			INSERT INTO tenant.saml_connections
				(tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, name_attribute, status)
			SELECT $1, $2, 'https://'||$3||'.okta.com/exk1a2b3cSEED',
				'https://'||$3||'.okta.com/app/'||$3||'_qeetid/exk1a2b3cSEED/sso/saml',
				'-----BEGIN CERTIFICATE-----' || chr(10) || 'MIIDdemoPlaceholderNotARealCertForDisplayOnly' || chr(10) || '-----END CERTIFICATE-----',
				'email', 'displayName', 'draft'
			WHERE NOT EXISTS (
				SELECT 1 FROM tenant.saml_connections WHERE tenant_id = $1 AND name = $2
			)
		`, tenantID, connName, oktaSub)
		must(err, "saml "+connName)
	}

	customers := []orgInput{
		{slug: "northwind", name: "Northwind Capital", domain: "northwindcapital.co", plan: "enterprise", region: "ap-south-1", currency: "INR", users: 15, groups: []string{"Platform", "Risk", "Compliance"}},
		{slug: "meridian", name: "Meridian Health", domain: "meridianhealth.io", plan: "pro", region: "us-east-1", currency: "USD", users: 12, groups: []string{"Clinical Apps", "IT"}},
		{slug: "lumen", name: "Lumen Labs", domain: "lumenlabs.dev", plan: "pro", region: "eu-west-1", currency: "EUR", users: 8, groups: []string{"Engineering", "Growth"}},
		{slug: "aster", name: "Aster Retail", domain: "asterretail.com", plan: "starter", region: "ap-south-1", currency: "INR", users: 6, groups: []string{"Storefront"}},
		{slug: "vertex", name: "Vertex Logistics", domain: "vertexlogistics.co", plan: "starter", region: "us-east-1", currency: "USD", users: 5, groups: []string{"Operations"}},
		{slug: "cobalt", name: "Cobalt Studios", domain: "cobaltstudios.io", plan: "free", region: "eu-west-1", currency: "EUR", users: 4, groups: []string{"Studio"}},
		{slug: "fjord", name: "Fjord Analytics", domain: "fjordanalytics.dev", plan: "free", region: "us-east-1", currency: "USD", users: 3, groups: nil},
	}
	type ownerRow struct{ email, company, plan string }
	var custOwners []ownerRow
	for _, c := range customers {
		t, o := seedOrg(c)
		custOwners = append(custOwners, ownerRow{o.Email, c.name, c.plan})
		switch c.slug {
		case "northwind": // Enterprise: SAML SSO + SCIM directory sync
			addSAML(t.ID, "Northwind Okta", "northwind")
			inTx("northwind scim", func(tx pgx.Tx) error {
				_, e := scimSvc.Rotate(ctx, tx, t.ID)
				return e
			})
		case "meridian": // Pro: Google social login
			_, err = socialSvc.UpsertProvider(ctx, social.CreateProviderInput{TenantID: t.ID, Provider: "google", ClientID: "meridian-google-client-id", ClientSecret: "meridian-google-secret", DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration"})
			must(err, "meridian social")
		case "lumen": // Pro (dev-tools company): GitHub social login
			_, err = socialSvc.UpsertProvider(ctx, social.CreateProviderInput{TenantID: t.ID, Provider: "github", ClientID: "lumen-github-client-id", ClientSecret: "lumen-github-secret"})
			must(err, "lumen social")
		}
	}
	fmt.Printf("  • customers     %d workspaces seeded with generated rosters\n", len(customers))

	// ---- Login history (sessions + login audit -> sessions page + analytics) ----
	// Vary IP (all TEST-NET documentation ranges) and user agent for realistic
	// analytics. Each sampled account signs in twice.
	ips := []string{"203.0.113.10", "203.0.113.42", "198.51.100.15", "192.0.2.77", "203.0.113.200"}
	agents := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
		"QeetSDK-Go/1.2.0",
	}
	loginCount := 0
	for n, email := range logins {
		for i := 0; i < 2; i++ {
			_, err := authSvc.Login(ctx, auth.LoginInput{
				Email: email, Password: seedPassword,
				IP: ips[(n+i)%len(ips)], UserAgent: agents[(n+i)%len(agents)],
			})
			must(err, "login "+email)
			loginCount++
		}
	}

	fmt.Printf("\n✅ Seed complete (%d sign-ins across %d accounts). Log in to the admin UI with any of:\n", loginCount, len(logins))
	fmt.Printf("   owner    saibabu@qeet.in   %s   (Qeet Group + Qeet Sandbox)\n", seedPassword)
	fmt.Printf("   admin    aarav@qeet.in     %s   (Qeet Group)\n", seedPassword)
	fmt.Printf("   engineer rohan@qeet.in     %s   (Qeet Group)\n", seedPassword)
	fmt.Printf("   member   sneha@qeet.in     %s   (Qeet Group)\n", seedPassword)
	fmt.Println("   Customer owners each own their own isolated workspace (printed below); all use the same password.")
	fmt.Println("   Workspaces: Qeet Group (Enterprise, ap-south-1) · Qeet Sandbox (Free) ·")
	fmt.Println("     Northwind Capital (Enterprise, ap-south-1) · Meridian Health (Pro, us-east-1) ·")
	fmt.Println("     Lumen Labs (Pro, eu-west-1) · Aster Retail (Starter, ap-south-1) ·")
	fmt.Println("     Vertex Logistics (Starter, us-east-1) · Cobalt Studios (Free, eu-west-1) · Fjord Analytics (Free, us-east-1)")
	fmt.Printf("   Example OAuth clients: %s (Next.js), qci_example_spa (React SPA) — see examples/\n", exampleClientID)
	fmt.Println("   Qeet Group is fully configured: billing, service accounts, secrets vault, auth hooks,")
	fmt.Println("   AI agents, verifiable credentials, invitations, domains, email templates, retention,")
	fmt.Println("   SIEM, IP rules, auth policy, notifications, LDAP & SAML — every screen has data.")
	fmt.Println("   Customer owner logins (each owns one isolated workspace):")
	for _, o := range custOwners {
		fmt.Printf("     %-40s %s   (%s · %s)\n", o.email, seedPassword, o.company, o.plan)
	}
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
