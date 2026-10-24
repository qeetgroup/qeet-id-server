package security

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/totp"
)

// Authenticator apps, recovery codes and push devices are enrolled through the
// MFA service side by side, then dated to Person.MFASince. Email and SMS
// factors and passkeys hold no secret and are written directly: an OTP factor
// is confirmed by a code only its inbox sees, a passkey by a browser ceremony.

// enrolSection is the summary section listing the test accounts' factors.
const enrolSection = "Second factors for test accounts (add the secret to any authenticator app)"

// enrolment is one person's factors as enrolled: what the run needs to date
// them and to print a test account's secret.
type enrolment struct {
	p      *world.Person
	secret string   // authenticator-app secret; "" without one
	codes  []string // recovery codes, in plain text
	push   *phone   // the linked phone; nil without push
	err    error
}

// phone is a person's phone as linked for push approval.
type phone struct {
	name, platform, token string
	appUA                 string
	id                    uuid.UUID // the device row, once linked
}

// enrolFactors enrols every person's second factors and dates them.
func enrolFactors(w *world.World) {
	var todo []*enrolment
	for _, o := range w.Orgs {
		for _, p := range o.People {
			if settleFactors(w, p) {
				e := &enrolment{p: p}
				if p.HasFactor("push") {
					e.push = newPhone(w, p)
				}
				todo = append(todo, e)
			}
		}
	}
	if len(todo) == 0 {
		return
	}
	earliest := todo[0].p.MFASince
	for _, e := range todo {
		if e.p.MFASince.Before(earliest) {
			earliest = e.p.MFASince
		}
	}
	w.At(earliest, func() {
		parallel(len(todo), runtime.GOMAXPROCS(0), func(i int) { enrol(w, todo[i]) })
	})
	for _, e := range todo {
		w.Check(e.err, "enrol second factors for "+e.p.Email)
	}

	batch := &pgx.Batch{}
	for _, e := range todo {
		date(w, batch, e)
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "date second factors")
	testAccountSecrets(w, todo)
}

// settleFactors fits a person's planned factors to their story and reports
// whether they hold any: none before they verified their address, set up
// before they left, and an authenticator app for every test account that has
// a factor, so a tester can always meet the challenge.
func settleFactors(w *world.World, p *world.Person) bool {
	if len(p.MFA) == 0 || p.ID == uuid.Nil {
		return false
	}
	if p.Unverified {
		p.MFA, p.MFASince = nil, time.Time{}
		return false
	}
	if p.Login != "" && !p.HasFactor("totp") {
		p.MFA = append(p.MFA, "totp", "recovery")
	}
	if _, ok := showcasePasskeys[p.Email]; ok && !p.HasFactor("passkey") && p.Org.Spec.Features.Passkeys {
		p.MFA = append(p.MFA, "passkey")
	}
	if earliest := p.Joined.Add(30 * time.Minute); p.MFASince.Before(earliest) {
		p.MFASince = earliest
	}
	if p.Status != world.StatusActive && !p.Since.IsZero() && !p.MFASince.Before(p.Since) {
		if p.Since.Sub(p.Joined) < 2*time.Hour {
			p.MFA, p.MFASince = nil, time.Time{}
			return false
		}
		p.MFASince = p.Joined.Add(p.Since.Sub(p.Joined) / 3)
	}
	if latest := w.Now.Add(-10 * time.Minute); p.MFASince.After(latest) {
		p.MFASince = latest
	}
	return true
}

// enrol sets up e's authenticator app and links its phone, through the MFA
// service as the account screens do. Safe to run alongside other enrolments;
// its transactions come from the owner's pool, leaving the API's to the
// service's own attempt counting.
func enrol(w *world.World, e *enrolment) {
	ctx, svc, p := w.Ctx, w.Deps.MFA.Service, e.p
	if p.HasFactor("totp") {
		tx, err := w.Admin.Begin(ctx)
		if e.err = err; err != nil {
			return
		}
		started, err := svc.StartEnroll(ctx, tx, p.ID, p.Email)
		if err == nil {
			err = tx.Commit(ctx)
		}
		_ = tx.Rollback(ctx)
		if e.err = err; err != nil {
			return
		}
		attempt, err := svc.ReserveAttempt(ctx, p.ID, mfa.PurposeTOTPEnroll)
		if e.err = err; err != nil {
			return
		}
		code, err := totp.Code(started.Secret, time.Now())
		if e.err = err; err != nil {
			return
		}
		tx, err = w.Admin.Begin(ctx)
		if e.err = err; err != nil {
			return
		}
		codes, err := svc.ConfirmEnroll(ctx, tx, attempt, code)
		if err == nil {
			err = tx.Commit(ctx)
		}
		_ = tx.Rollback(ctx)
		if e.err = err; err != nil {
			return
		}
		e.secret, e.codes = started.Secret, codes
	}
	if e.push != nil {
		d, _, err := svc.RegisterPushDevice(ctx, p.ID, e.push.name, e.push.token, e.push.platform)
		e.push.id, e.err = d.ID, err
	}
}

// parallel runs fn(0..n-1) on workers goroutines and waits for them.
func parallel(n, workers int, fn func(i int)) {
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := range n {
		next <- i
	}
	close(next)
	wg.Wait()
}

// date moves e's factors to when the person set them up, adds the factors
// written directly, and records the enrolments in the audit trail.
func date(w *world.World, b *pgx.Batch, e *enrolment) {
	p := e.p
	at := p.MFASince
	tid := p.Org.ID
	self := func(t time.Time, action string, meta map[string]any) {
		w.Audit(t, audit.Event{TenantID: &tid, ActorUserID: &p.ID, Action: action, ResourceType: "user",
			ResourceID: &p.ID, IP: p.Device.IP, UserAgent: p.Device.UserAgent, Metadata: meta})
	}

	if p.HasFactor("passkey") {
		addPasskeys(w, b, p)
	}
	if e.secret != "" {
		b.Queue(`UPDATE auth.mfa_totp SET created_at = $2, confirmed_at = $3 WHERE user_id = $1`,
			p.ID, at.Add(-2*time.Minute), at)
		b.Queue(`UPDATE auth.mfa_recovery_codes SET created_at = $2 WHERE user_id = $1`, p.ID, at)
		self(at.Add(-2*time.Minute), "mfa.totp_enroll_started", map[string]any{"replacing": false})
		self(at, "mfa.totp_enrolled", map[string]any{"recovery_codes_minted": len(e.codes)})
		if p.Login == "" && w.Chance(0.15) {
			useRecoveryCodes(w, b, p)
		}
	}
	for _, channel := range []string{"email", "sms"} {
		if !p.HasFactor(channel) {
			continue
		}
		dest := p.Email
		if channel == "sms" {
			dest = p.Phone
		}
		b.Queue(`INSERT INTO auth.mfa_otp_factors (user_id, channel, destination, verified_at, created_at)
			VALUES ($1, $2, $3, $4, $5)`, p.ID, channel, dest, at, at.Add(-90*time.Second))
		self(at, "mfa.otp_factor_added", nil)
	}
	if e.push != nil {
		linked := at.Add(4 * time.Minute)
		seen := lastSeen(w, p, linked)
		relinked := linked
		if seen.Sub(linked) > 150*24*time.Hour {
			relinked = seen.Add(-time.Duration(w.Rand.IntN(60)) * 24 * time.Hour)
		}
		b.Queue(`UPDATE auth.mfa_push_devices SET created_at = $2, last_seen_at = $3, device_token_expires_at = $4
			WHERE user_id = $1`, p.ID, linked, seen, relinked.Add(180*24*time.Hour))
		w.Audit(linked, audit.Event{TenantID: &tid, ActorUserID: &p.ID, ActorType: "device", Action: "mfa.push_device_linked",
			ResourceType: "push_device", ResourceID: &e.push.id, IP: p.Mobile.IP, UserAgent: e.push.appUA,
			Metadata: map[string]any{"platform": e.push.platform}})
	}
}

// lastSeen is when p last used a factor: in the last few days for people still
// here, else shortly before they left; never before since.
func lastSeen(w *world.World, p *world.Person, since time.Time) time.Time {
	end := w.Now.Add(-time.Hour)
	if p.Status != world.StatusActive && !p.Since.IsZero() {
		end = p.Since.Add(-2 * time.Hour)
	}
	start := end.Add(-6 * 24 * time.Hour)
	if start.Before(since) {
		start = since
	}
	return w.Between(start, end)
}

// useRecoveryCodes marks one or two of p's recovery codes used, as when a phone
// was left at home.
func useRecoveryCodes(w *world.World, b *pgx.Batch, p *world.Person) {
	rows, err := w.Admin.Query(w.Ctx, `SELECT id FROM auth.mfa_recovery_codes WHERE user_id = $1 ORDER BY id`, p.ID)
	w.Check(err, "list recovery codes")
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	w.Check(err, "list recovery codes")
	if len(ids) == 0 {
		return
	}
	end := lastSeen(w, p, p.MFASince.Add(24*time.Hour))
	tid := p.Org.ID
	for _, id := range ids[:1+w.Rand.IntN(2)] {
		used := w.WorkHours(w.Between(p.MFASince.Add(24*time.Hour), end), p.Loc)
		if used.After(w.Now) || used.Before(p.MFASince) {
			continue
		}
		b.Queue(`UPDATE auth.mfa_recovery_codes SET used_at = $2 WHERE id = $1`, id, used)
		w.Audit(used, audit.Event{TenantID: &tid, ActorUserID: &p.ID, Action: "mfa.recovery_code_used", ResourceType: "user",
			ResourceID: &p.ID, IP: p.Device.IP, UserAgent: p.Device.UserAgent, Metadata: map[string]any{"recovery_code_id": id}})
	}
}

// androidModels names the Android phones the census hands out, by the model
// code in their user agent.
var androidModels = map[string]string{
	"SM-S931B": "Galaxy S25", "Pixel 9": "Pixel 9", "CPH2581": "OnePlus 12",
	"SM-A556E": "Galaxy A55 5G", "2312DRA50I": "Redmi Note 13 Pro 5G",
}

// newPhone is p's phone as the Qeet ID app links it: iOS reports the name its
// owner gave it, Android the model.
func newPhone(w *world.World, p *world.Person) *phone {
	const tokenChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	tok := make([]byte, 22)
	for i := range tok {
		tok[i] = tokenChars[w.Rand.IntN(len(tokenChars))]
	}
	ph := &phone{token: "ExponentPushToken[" + string(tok) + "]"}
	ua := p.Mobile.UserAgent
	switch {
	case strings.Contains(ua, "iPad"):
		ph.name, ph.platform = p.First+"’s iPad", "ios"
		ph.appUA = "QeetID/1.4.2 (iPad; iPadOS 18.6) Expo/53"
	case strings.Contains(ua, "iPhone"):
		ph.name, ph.platform = p.First+"’s iPhone", "ios"
		ph.appUA = "QeetID/1.4.2 (iPhone; iOS 18.6) Expo/53"
	default:
		ph.name, ph.platform = "Android phone", "android"
		for code, model := range androidModels {
			if strings.Contains(ua, code) {
				ph.name = model
			}
		}
		ph.appUA = "QeetID/1.4.2 (Android 15; " + ph.name + ") Expo/53"
	}
	return ph
}

// testAccountSecrets gives each test account's authenticator app a fixed
// secret that survives a reseed (the service's own when SECRETS_KEY is unset),
// checks the MFA service accepts its code, and prints the secrets and one set
// of recovery codes.
func testAccountSecrets(w *world.World, done []*enrolment) {
	var tests []*enrolment
	for _, e := range done {
		if e.p.Login != "" && e.secret != "" {
			tests = append(tests, e)
		}
	}
	if len(tests) == 0 {
		return
	}
	box := reproducedCipher(w, tests[0])
	for _, e := range tests {
		p := e.p
		if box != nil {
			e.secret = fixedSecret(p.Email)
			ct, nonce, err := box.Seal(p.ID, "mfa-totp", p.ID.String(), []byte(e.secret))
			w.Check(err, "seal the TOTP secret of "+p.Email)
			w.Exec("fix the TOTP secret of "+p.Email,
				`UPDATE auth.mfa_totp SET secret_ct = $2, secret_nonce = $3, last_used_step = NULL WHERE user_id = $1`, p.ID, ct, nonce)
		} else {
			w.Exec("reset the TOTP step of "+p.Email, `UPDATE auth.mfa_totp SET last_used_step = NULL WHERE user_id = $1`, p.ID)
		}
		acceptsCode(w, p, e.secret)
		w.Note(enrolSection, "%-38s %s", p.Email, e.secret)
		w.Note(enrolSection, "  %s", totp.ProvisioningURL(e.secret, w.Cfg.JWTIssuer, p.Email))
	}
	if box == nil {
		w.Note(enrolSection, "(SECRETS_KEY is unset, so these secrets change with every seed)")
	}
	shown := tests[0]
	for _, e := range tests {
		if e.p.Email == "aarav@qeet.in" {
			shown = e
		}
	}
	w.Note(enrolSection, "Recovery codes for %s (each works once): %s", shown.p.Email, strings.Join(shown.codes, " "))
}

// fixedSecret is a test account's authenticator-app secret, the same on every
// seed: 20 bytes derived from the address, base32 as authenticator apps take it.
func fixedSecret(email string) string {
	sum := sha256.Sum256([]byte("qeet-id dev seed TOTP " + strings.ToLower(email)))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:20])
}

// reproducedCipher returns the API's cipher for second-factor secrets when the
// seed can rebuild it from the configured key, proven by opening the secret
// the MFA service sealed for e; nil otherwise.
func reproducedCipher(w *world.World, e *enrolment) *envelope.Cipher {
	kp, err := bootstrap.SecretsKeyProvider(w.Ctx, w.Cfg)
	if err != nil {
		return nil
	}
	key, err := kp.DataKey(w.Ctx)
	if err != nil {
		return nil
	}
	box, err := envelope.New(key)
	if err != nil {
		return nil
	}
	var ct, nonce []byte
	w.Check(w.Admin.QueryRow(w.Ctx, `SELECT secret_ct, secret_nonce FROM auth.mfa_totp WHERE user_id = $1`, e.p.ID).
		Scan(&ct, &nonce), "read a sealed TOTP secret")
	plain, err := box.Open(e.p.ID, "mfa-totp", e.p.ID.String(), ct, nonce)
	if err != nil || string(plain) != e.secret {
		return nil
	}
	return box
}

// acceptsCode checks, in a transaction it rolls back, that the MFA service
// accepts the current code of secret as p's second factor.
func acceptsCode(w *world.World, p *world.Person, secret string) {
	code, err := totp.Code(secret, time.Now())
	w.Check(err, "compute a TOTP code")
	tx, err := w.Pool.Begin(w.Ctx)
	w.Check(err, "begin TOTP check")
	defer tx.Rollback(w.Ctx) // a check, never committed
	kind, err := w.Deps.MFA.Service.VerifyForLoginTx(w.Ctx, tx, p.ID, code)
	w.Check(err, "verify a TOTP code for "+p.Email)
	if kind != "totp" {
		w.Check(fmt.Errorf("the MFA service refused the seeded secret (got %q)", kind), "check the TOTP secret of "+p.Email)
	}
}
