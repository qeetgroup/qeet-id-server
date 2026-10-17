//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/policy"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An organisation's MFA requirement, and an account marked as requiring MFA,
// are enforced at password sign-in: an account that must use a second factor
// is challenged, and one holding none sets up an authenticator app before any
// session — except in the grace period, when the accounts the organisation
// already had may put that off.

// requireMFA sets the organisation's requirement as turned on at since (nil:
// not recorded), with graceDays of grace.
func requireMFA(t *testing.T, ctx context.Context, tenantID uuid.UUID, enforcement string, graceDays int, since *time.Time) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id) DO UPDATE SET mfa_enforcement = EXCLUDED.mfa_enforcement,
			mfa_grace_days = EXCLUDED.mfa_grace_days, mfa_enforced_since = EXCLUDED.mfa_enforced_since`,
		tenantID, enforcement, graceDays, since); err != nil {
		t.Fatal(err)
	}
}

// writeRole creates a role in the organisation granting a write permission.
func writeRole(t *testing.T, ctx context.Context, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var permID, roleID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO rbac.permissions (key) VALUES ('tenant.write')
		ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id`).Scan(&permID); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, $2) RETURNING id`,
		tenantID, uniqueSlug("admin")).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO rbac.role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleID, permID); err != nil {
		t.Fatal(err)
	}
	return roleID
}

// enforced is a sign-in's answer: a challenge, possibly an enrolment one, or
// a session.
type enforced struct {
	challenge
	EnrollmentRequired bool       `json:"enrollment_required"`
	EnrollmentDueAt    *time.Time `json:"enrollment_due_at"`
	RecoveryCodes      []string   `json:"recovery_codes"`
	UserID             string     `json:"user_id"`
}

func (f *factorFixture) signInEnforced(t *testing.T, email string) enforced {
	t.Helper()
	rr := f.post("/v1/auth/login", map[string]string{"email": email, "password": factorPassword})
	if rr.Code != http.StatusOK {
		t.Fatalf("sign in: %d %s", rr.Code, rr.Body.String())
	}
	var e enforced
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	return e
}

func (f *factorFixture) completeEnforced(path string, body map[string]any) (*httptest.ResponseRecorder, enforced) {
	rr := f.post(path, body)
	var e enforced
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	return rr, e
}

// holdTOTP gives the account a confirmed authenticator app.
func (f *factorFixture) holdTOTP(t *testing.T, ctx context.Context, userID uuid.UUID) string {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.mfa.StartEnroll(ctx, tx, userID, "holder@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := mfaConfirmEnroll(ctx, f.mfa, userID, totpCodeAtStep(t, e.Secret, -1)); err != nil {
		t.Fatal(err)
	}
	return e.Secret
}

// lastChallengeReason is the reason the account's latest challenge was
// audited with.
func lastChallengeReason(t *testing.T, ctx context.Context, userID uuid.UUID) string {
	t.Helper()
	var reason string
	if err := testPool.QueryRow(ctx, `
		SELECT metadata->>'reason' FROM audit.events
		WHERE resource_id = $1 AND action = 'auth.mfa_challenged'
		ORDER BY created_at DESC LIMIT 1`, userID).Scan(&reason); err != nil {
		t.Fatalf("no auth.mfa_challenged audit: %v", err)
	}
	return reason
}

// TestRequiredMFAChallengesAnAccountHoldingAFactor: with the organisation
// requiring MFA, an account holding a factor gets a challenge, not a session,
// audited as required by the organisation.
func TestRequiredMFAChallengesAnAccountHoldingAFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	requireMFA(t, ctx, f.tenantID, "required", 0, nil)
	me, email := f.member(t, ctx)
	f.holdTOTP(t, ctx, me)

	e := f.signInEnforced(t, email)
	if !e.MFARequired || e.AccessToken != "" || e.EnrollmentRequired || len(e.Factors) == 0 {
		t.Fatalf("got %+v, want a challenge for the factor held", e)
	}
	if r := lastChallengeReason(t, ctx, me); r != "tenant_required" {
		t.Fatalf("challenge audited as %q, want tenant_required", r)
	}
}

// TestRequiredMFARoutesAnAccountWithoutAFactorIntoEnrolment: with the
// organisation requiring MFA, an account holding no factor gets an enrolment
// challenge and no session. It cannot skip it or meet it with anything but a
// code from the authenticator app it sets up through it; that code signs it
// in with fresh recovery codes, and its next sign-in is challenged for the app.
func TestRequiredMFARoutesAnAccountWithoutAFactorIntoEnrolment(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	requireMFA(t, ctx, f.tenantID, "required", 0, nil)
	me, email := f.member(t, ctx)

	e := f.signInEnforced(t, email)
	if !e.MFARequired || e.AccessToken != "" || !e.EnrollmentRequired || e.EnrollmentDueAt != nil ||
		len(e.Factors) != 0 || len(e.Methods) != 1 || e.Methods[0] != "totp" {
		t.Fatalf("got %+v, want an enrolment challenge with no grace", e)
	}
	if r := lastChallengeReason(t, ctx, me); r != "tenant_required" {
		t.Fatalf("challenge audited as %q, want tenant_required", r)
	}
	token := e.MFAToken

	// No way round the setup.
	if rr, _ := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": token, "skip": true}); rr.Code != http.StatusForbidden ||
		errorCode(t, rr) != errs.CodeMFAEnrollmentRequired {
		t.Fatalf("skip with no grace period: %d %s, want 403 %s", rr.Code, rr.Body.String(), errs.CodeMFAEnrollmentRequired)
	}
	if rr, _ := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": token, "code": "123456"}); rr.Code != http.StatusBadRequest ||
		errorCode(t, rr) != errs.CodeMFAEnrollNotStarted {
		t.Fatalf("code before the app is set up: %d %s, want 400 %s", rr.Code, rr.Body.String(), errs.CodeMFAEnrollNotStarted)
	}
	for _, path := range []string{"/v1/auth/mfa/send", "/v1/auth/mfa/passkey/begin", "/v1/auth/mfa/push"} {
		if rr := f.post(path, map[string]any{"mfa_token": token, "factor_id": uuid.New()}); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s on an enrolment challenge: %d %s, want 400", path, rr.Code, rr.Body.String())
		}
	}

	rr := f.post("/v1/auth/mfa/enroll", map[string]any{"mfa_token": token})
	if rr.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rr.Code, rr.Body.String())
	}
	var app struct {
		Secret          string `json:"secret"`
		ProvisioningURL string `json:"provisioning_url"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &app)
	if app.Secret == "" || !strings.HasPrefix(app.ProvisioningURL, "otpauth://totp/") {
		t.Fatalf("enroll returned %+v", app)
	}
	// Still no session: a wrong code is counted and refused.
	if rr, _ := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": token, "code": "000000"}); rr.Code == http.StatusOK {
		t.Fatalf("a wrong code signed in: %s", rr.Body.String())
	}
	rr, done := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": token, "code": totpCodeAtStep(t, app.Secret, -1)})
	if rr.Code != http.StatusOK || done.AccessToken == "" || len(done.RecoveryCodes) != 10 {
		t.Fatalf("confirming the app: %d %s, want a session and 10 recovery codes", rr.Code, rr.Body.String())
	}
	var enrolled int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM audit.events WHERE resource_id = $1 AND action = 'mfa.totp_enrolled'`, me).Scan(&enrolled); err != nil || enrolled != 1 {
		t.Fatalf("mfa.totp_enrolled audits: %d (%v), want 1", enrolled, err)
	}
	// The challenge is spent.
	if rr, _ := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": token, "code": totpCodeAtStep(t, app.Secret, 0)}); rr.Code == http.StatusOK {
		t.Fatal("the enrolment challenge was met twice")
	}

	next := f.signInEnforced(t, email)
	if !next.MFARequired || next.EnrollmentRequired || len(next.Methods) == 0 || next.Methods[0] != "totp" {
		t.Fatalf("next sign-in: %+v, want a challenge for the app set up", next)
	}
}

// TestHostedLoginRoutesAnAccountWithoutAFactorIntoEnrolment: the hosted login
// sets no SSO cookie before the setup either, and the confirming code sets it
// along with the new recovery codes.
func TestHostedLoginRoutesAnAccountWithoutAFactorIntoEnrolment(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	requireMFA(t, ctx, f.tenantID, "required", 0, nil)
	_, email := f.member(t, ctx)

	rr := f.post("/v1/auth/session", map[string]string{"email": email, "password": factorPassword})
	var e enforced
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if rr.Code != http.StatusOK || !e.EnrollmentRequired || e.MFAToken == "" || rr.Header().Get("Set-Cookie") != "" {
		t.Fatalf("hosted sign-in: %d %s (cookie %q), want an enrolment challenge and no cookie",
			rr.Code, rr.Body.String(), rr.Header().Get("Set-Cookie"))
	}
	rr = f.post("/v1/auth/mfa/enroll", map[string]any{"mfa_token": e.MFAToken})
	var app struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &app)
	rr, done := f.completeEnforced("/v1/auth/session/mfa", map[string]any{
		"mfa_token": e.MFAToken, "code": totpCodeAtStep(t, app.Secret, -1), "remember": true})
	if rr.Code != http.StatusOK || done.UserID == "" || len(done.RecoveryCodes) != 10 ||
		!strings.Contains(rr.Header().Get("Set-Cookie"), "qe_ls=") {
		t.Fatalf("confirming the app: %d %s, want the SSO cookie and recovery codes", rr.Code, rr.Body.String())
	}
}

// TestAdminOnlyMFAChallengesAdministratorsOnly: admin_only challenges an
// account holding a role that grants a write permission — directly or through
// a group — and leaves other accounts signing in as before.
func TestAdminOnlyMFAChallengesAdministratorsOnly(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	requireMFA(t, ctx, f.tenantID, "admin_only", 0, nil)
	role := writeRole(t, ctx, f.tenantID)

	admin, adminEmail := f.member(t, ctx)
	if _, err := testPool.Exec(ctx, `INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
		admin, f.tenantID, role); err != nil {
		t.Fatal(err)
	}
	viaGroup, groupEmail := f.member(t, ctx)
	var group uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'admins') RETURNING id`,
		f.tenantID).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.group_members (group_id, user_id, tenant_id) VALUES ($1, $2, $3);`,
		group, viaGroup, f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO rbac.group_roles (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`,
		f.tenantID, group, role); err != nil {
		t.Fatal(err)
	}
	_, memberEmail := f.member(t, ctx)

	for who, email := range map[string]string{"administrator": adminEmail, "administrator through a group": groupEmail} {
		if e := f.signInEnforced(t, email); !e.EnrollmentRequired || e.AccessToken != "" {
			t.Fatalf("%s signed in without a second factor: %+v", who, e)
		}
	}
	if r := lastChallengeReason(t, ctx, admin); r != "admin_required" {
		t.Fatalf("challenge audited as %q, want admin_required", r)
	}
	if e := f.signInEnforced(t, memberEmail); e.MFARequired || e.AccessToken == "" {
		t.Fatalf("a member without a write role was challenged: %+v", e)
	}
}

// TestMarkedAccountMustUseMFA: an account an administrator marked as
// requiring MFA is challenged though its organisation leaves MFA optional,
// with no grace period.
func TestMarkedAccountMustUseMFA(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	past := time.Now().Add(-time.Hour)
	requireMFA(t, ctx, f.tenantID, "optional", 30, &past)
	me, email := f.member(t, ctx)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET mfa_required = TRUE, created_at = NOW() - INTERVAL '1 day' WHERE id = $1`, me); err != nil {
		t.Fatal(err)
	}

	e := f.signInEnforced(t, email)
	if !e.EnrollmentRequired || e.EnrollmentDueAt != nil || e.AccessToken != "" {
		t.Fatalf("got %+v, want an enrolment challenge with no grace", e)
	}
	if r := lastChallengeReason(t, ctx, me); r != "user_required" {
		t.Fatalf("challenge audited as %q, want user_required", r)
	}
	f.holdTOTP(t, ctx, me)
	if e := f.signInEnforced(t, email); !e.MFARequired || e.EnrollmentRequired {
		t.Fatalf("got %+v, want a challenge for the app held", e)
	}
	if r := lastChallengeReason(t, ctx, me); r != "user_required" {
		t.Fatalf("challenge audited as %q, want user_required", r)
	}
}

// TestOptionalMFAIsDrivenByWhatIsHeld: left optional, an account without a
// factor signs in with its password alone and one holding a factor is
// challenged, audited as its own choice.
func TestOptionalMFAIsDrivenByWhatIsHeld(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	requireMFA(t, ctx, f.tenantID, "optional", 0, nil)
	_, plainEmail := f.member(t, ctx)
	if e := f.signInEnforced(t, plainEmail); e.MFARequired || e.AccessToken == "" {
		t.Fatalf("an account without a factor was challenged: %+v", e)
	}
	me, email := f.member(t, ctx)
	f.holdTOTP(t, ctx, me)
	if e := f.signInEnforced(t, email); !e.MFARequired || e.EnrollmentRequired {
		t.Fatalf("an account holding a factor was not challenged: %+v", e)
	}
	if r := lastChallengeReason(t, ctx, me); r != "enrolled" {
		t.Fatalf("challenge audited as %q, want enrolled", r)
	}
}

// TestGracePeriodLetsExistingAccountsPutSetupOff: in the grace period an
// account that existed when the requirement was turned on is prompted to set
// up a factor and may skip it — signing in with no factor met, audited — while
// one created after must set one up, and once the grace period ends so must
// everyone.
func TestGracePeriodLetsExistingAccountsPutSetupOff(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	existing, existingEmail := f.member(t, ctx)
	since := time.Now().Add(time.Second)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET created_at = $2 WHERE id = $1`, existing, since.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	requireMFA(t, ctx, f.tenantID, "required", 14, &since)

	e := f.signInEnforced(t, existingEmail)
	want := since.Add(14 * 24 * time.Hour)
	if !e.EnrollmentRequired || e.EnrollmentDueAt == nil || e.EnrollmentDueAt.Sub(want).Abs() > time.Second || e.AccessToken != "" {
		t.Fatalf("got %+v, want an enrolment prompt due %v", e, want)
	}
	rr, done := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": e.MFAToken, "skip": true})
	if rr.Code != http.StatusOK || done.AccessToken == "" || len(done.RecoveryCodes) != 0 {
		t.Fatalf("skipping in the grace period: %d %s", rr.Code, rr.Body.String())
	}
	var deferred int
	var method string
	if err := testPool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM audit.events WHERE resource_id = $1 AND action = 'auth.mfa_enrollment_deferred'),
		       (SELECT metadata->>'method' FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.login_succeeded'
		        ORDER BY created_at DESC LIMIT 1)`, existing).Scan(&deferred, &method); err != nil {
		t.Fatal(err)
	}
	if deferred != 1 || method != "password" {
		t.Fatalf("deferral audits %d, sign-in method %q; want 1 and password", deferred, method)
	}

	// An account created after the requirement was turned on has no grace.
	newcomer, newEmail := f.member(t, ctx)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET created_at = $2 WHERE id = $1`, newcomer, since.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if e := f.signInEnforced(t, newEmail); !e.EnrollmentRequired || e.EnrollmentDueAt != nil {
		t.Fatalf("an account created after enforcement got %+v, want an enrolment challenge with no grace", e)
	}

	// The grace period ends: the skip is refused, even on a challenge raised
	// before it ended.
	e = f.signInEnforced(t, existingEmail)
	ended := time.Now().Add(-15 * 24 * time.Hour)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET created_at = $2 WHERE id = $1`, existing, ended.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	requireMFA(t, ctx, f.tenantID, "required", 14, &ended)
	if rr, _ := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": e.MFAToken, "skip": true}); rr.Code != http.StatusForbidden {
		t.Fatalf("skip after the grace period: %d %s, want 403", rr.Code, rr.Body.String())
	}
	if e := f.signInEnforced(t, existingEmail); !e.EnrollmentRequired || e.EnrollmentDueAt != nil {
		t.Fatalf("after the grace period got %+v, want an enrolment challenge with no grace", e)
	}
}

// TestSelfRegistrationSetsUpAFactorFirst: where the organisation requires
// MFA, hosted self-registration answers an enrolment challenge instead of an
// SSO session.
func TestSelfRegistrationSetsUpAFactorFirst(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.auth_policy (tenant_id, self_registration_enabled) VALUES ($1, TRUE)
		ON CONFLICT (tenant_id) DO UPDATE SET self_registration_enabled = TRUE`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	requireMFA(t, ctx, f.tenantID, "required", 30, nil)

	u, res, err := f.auth.RegisterInTenant(ctx, f.tenantID, uniqueSlug("joiner")+"@example.com", factorPassword, "", "203.0.113.9", "test")
	if err != nil {
		t.Fatal(err)
	}
	if res.RawCookie != "" || !res.MFARequired || !res.EnrollmentRequired || res.EnrollmentDueAt != nil || res.UserID != u.ID {
		t.Fatalf("registration returned %+v, want an enrolment challenge and no session", res)
	}
}

// TestPolicyRecordsWhenMFAWasTurnedOn: the start of enforcement is recorded
// when the requirement goes from optional to on, kept while it stays on, and
// cleared when it goes back to optional.
func TestPolicyRecordsWhenMFAWasTurnedOn(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa-since"))
	repo := policy.NewRepository(testPool)
	save := func(enforcement string) *time.Time {
		t.Helper()
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		since, err := repo.Upsert(ctx, tx, policy.Policy{TenantID: tenantID, IPAllowlist: []string{}, IPDenylist: []string{},
			PasswordMinLength: 8, PasswordComplexity: "standard", SessionMaxAge: policy.Duration(24 * time.Hour),
			SessionIdleTimeout: policy.Duration(time.Hour), SessionLimitAction: "evict_oldest",
			MFAEnforcement: enforcement, MFAGraceDays: 7})
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return since
	}
	if s := save("optional"); s != nil {
		t.Fatalf("optional recorded a start: %v", s)
	}
	on := save("required")
	if on == nil {
		t.Fatal("turning MFA on recorded no start")
	}
	if s := save("admin_only"); s == nil || !s.Equal(*on) {
		t.Fatalf("moving to admin_only changed the start: %v, want %v", s, on)
	}
	if s := save("optional"); s != nil {
		t.Fatalf("turning MFA off kept the start: %v", s)
	}
	got, err := repo.Get(ctx, tenantID)
	if err != nil || got.MFAGraceDays != 7 || got.MFAEnforcedSince != nil {
		t.Fatalf("read back %+v (%v)", got, err)
	}
}

// TestMFAEvidenceReportsEnforcement: the compliance evidence reports whether
// MFA is enforced at sign-in — failing while optional or during a grace
// period — not merely the stored setting.
func TestMFAEvidenceReportsEnforcement(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa-evidence"))
	svc := gdpr.NewEvidenceService(testPool, audit.NewVerifier(testPool), false)
	mfaControl := func() gdpr.ControlResult {
		t.Helper()
		run, err := svc.Generate(ctx, tenantID, "soc2", nil)
		if err != nil {
			t.Fatal(err)
		}
		full, err := svc.GetRun(ctx, tenantID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range full.Controls {
			if c.ID == "CC6.1-MFA" {
				return c
			}
		}
		t.Fatal("no CC6.1-MFA control")
		return gdpr.ControlResult{}
	}

	if c := mfaControl(); c.Status != gdpr.ControlFail || !strings.Contains(c.Detail, "not enforced") {
		t.Fatalf("no policy: %+v", c)
	}
	recent := time.Now().Add(-time.Hour)
	requireMFA(t, ctx, tenantID, "required", 30, &recent)
	if c := mfaControl(); c.Status != gdpr.ControlFail || !strings.Contains(c.Detail, "grace period") {
		t.Fatalf("required in its grace period: %+v", c)
	}
	requireMFA(t, ctx, tenantID, "required", 0, &recent)
	createTenantUser(t, ctx, tenantID, uniqueSlug("nofactor")+"@example.com")
	if c := mfaControl(); c.Status != gdpr.ControlPass || !strings.Contains(c.Detail, "enforced at sign-in for every account") ||
		!strings.Contains(c.Detail, "1 account(s) hold none") {
		t.Fatalf("required: %+v", c)
	}
	requireMFA(t, ctx, tenantID, "admin_only", 0, &recent)
	if c := mfaControl(); c.Status != gdpr.ControlPass || !strings.Contains(c.Detail, "administrators") {
		t.Fatalf("admin_only: %+v", c)
	}
}
