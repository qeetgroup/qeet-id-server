package accounts

import (
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/policy"
	"github.com/qeetgroup/qeet-id-server/internal/operations/retention"
)

// security is an organisation's security policy: how long
// sessions last and who must use a second factor.
type security struct {
	maxAge      time.Duration
	idle        time.Duration
	maxSessions int // 0: no limit
	stepUp      time.Duration
	methods     []string
}

// securityPolicies are the organisations that set their own security policy.
// The MFA requirement and grace period come from each one's Features.
var securityPolicies = map[string]security{
	"qeet":      {maxAge: 7 * 24 * time.Hour, idle: 24 * time.Hour, stepUp: 10 * time.Minute},
	"northwind": {maxAge: 12 * time.Hour, idle: 30 * time.Minute, maxSessions: 5, stepUp: 5 * time.Minute, methods: []string{"totp", "webauthn"}},
	"meridian":  {maxAge: 12 * time.Hour, idle: 15 * time.Minute, stepUp: 5 * time.Minute},
	"lumen":     {maxAge: 30 * 24 * time.Hour, idle: 7 * 24 * time.Hour, stepUp: 15 * time.Minute},
	"aster":     {maxAge: 14 * 24 * time.Hour, idle: 72 * time.Hour, stepUp: 5 * time.Minute},
	"kestrel":   {maxAge: 24 * time.Hour, idle: time.Hour, stepUp: 5 * time.Minute},
}

// signIn is how an organisation's people may sign in, beyond its Features.
type signIn struct {
	minLength                 int
	upper, number, symbol     bool
	magicTTL                  int // minutes
	remember                  bool
	rememberDays              int
	lockThreshold, lockWindow int // failed attempts, minutes; 0: platform default
	lockDuration              int // minutes
}

// signInPolicies are the organisations that set their own sign-in policy.
var signInPolicies = map[string]signIn{
	"qeet":      {minLength: 12, upper: true, number: true, magicTTL: 30, remember: true, rememberDays: 30},
	"northwind": {minLength: 14, upper: true, number: true, symbol: true, lockThreshold: 3, lockWindow: 15, lockDuration: 30},
	"meridian":  {minLength: 12, number: true, symbol: true, lockThreshold: 5, lockWindow: 10, lockDuration: 20},
	"lumen":     {minLength: 10, magicTTL: 15, remember: true, rememberDays: 30},
	"aster":     {minLength: 8, magicTTL: 30, remember: true, rememberDays: 60},
	"vertex":    {minLength: 8},
	"kestrel":   {minLength: 10, number: true, remember: true, rememberDays: 7},
}

// retentionDays is how long each organisation keeps deleted accounts before
// they are purged; 0 keeps them until someone purges them by hand. Every
// window outlasts the oldest seeded deletion, so the API's hourly sweep
// leaves the deleted accounts in place.
var retentionDays = map[string]int{
	"qeet": 90, "northwind": 365, "meridian": 180, "lumen": 60, "kestrel": 90, "aster": 0, "cobalt": 0,
}

// policies sets the organisation's security, sign-in and retention policies
// through the console's own requests, at the points its story puts them:
// sign-in rules and MFA enforcement in the first days, a later tightening of
// sessions at Northwind, retention once people started leaving.
func (s *seeder) policies(o *world.Org) {
	w, slug := s.w, o.Spec.Slug
	f := o.Spec.Features
	path := "/tenants/" + o.ID.String()

	if si, ok := signInPolicies[slug]; ok {
		ttl := si.magicTTL
		if ttl == 0 {
			ttl = 60
		}
		p := authpolicy.Policy{
			PasswordEnabled: true, PasswordMinLength: si.minLength,
			PasswordRequireUppercase: si.upper, PasswordRequireNumber: si.number, PasswordRequireSymbol: si.symbol,
			MagicLinkEnabled: f.MagicLink, MagicLinkTTLMinutes: ttl,
			PasskeyEnabled: f.Passkeys, SelfRegistrationEnabled: f.SelfSignup,
			RememberDeviceEnabled: si.remember, RememberDeviceDays: si.rememberDays,
		}
		if si.lockThreshold > 0 {
			p.LockoutThreshold, p.LockoutWindowMinutes, p.LockoutDurationMinutes = &si.lockThreshold, &si.lockWindow, &si.lockDuration
		}
		at := w.WorkHours(o.Spec.Since.Add(26*time.Hour), o.Loc)
		if slug == "vertex" {
			at = o.Spec.Since.Add(5 * time.Hour)
		}
		actor := by(o, at)
		w.At(at, func() { s.api.do(o, actor, "", "PUT", path+"/auth-policy", p) })
	}

	if sp, ok := securityPolicies[slug]; ok {
		p := policy.Policy{
			SessionMaxAge: policy.Duration(sp.maxAge), SessionIdleTimeout: policy.Duration(sp.idle),
			MFAEnforcement: f.MFA, MFAGraceDays: f.MFAGrace,
			StepUpWindow: policy.Duration(sp.stepUp), StepUpMethods: sp.methods, Settings: map[string]any{},
		}
		if p.MFAEnforcement == "" {
			p.MFAEnforcement = "optional"
		}
		// Meridian let its people take a week to set up MFA when it began
		// requiring it of administrators.
		if f.MFA == "admin_only" && p.MFAGraceDays == 0 {
			p.MFAGraceDays = 7
		}
		first := p
		if slug == "northwind" {
			// Sessions began at an hour idle with no cap, tightened after the
			// RBI cyber-security audit.
			first.SessionIdleTimeout = policy.Duration(time.Hour)
		}
		at := o.Spec.Since.Add(27 * time.Hour)
		if f.MFA == "admin_only" {
			at = o.Spec.Since.Add(10 * 24 * time.Hour)
		}
		at = w.WorkHours(at, o.Loc)
		actor := by(o, at, world.RoleITAdmin, world.RoleAdmin, world.RoleSecurity)
		w.At(at, func() { s.api.do(o, actor, "", "PUT", path+"/policy", first) })
		if slug == "northwind" {
			p.MaxSessions = &sp.maxSessions
			at := w.Days(46)
			actor := by(o, at, world.RoleSecurity, world.RoleITAdmin)
			w.At(at, func() { s.api.do(o, actor, "", "PUT", path+"/policy", p) })
		}
	}

	if days, ok := retentionDays[slug]; ok {
		p := retention.Policy{DeletedUsersEnabled: days > 0, DeletedUsersDays: max(days, 30)}
		at := o.Spec.Since.Add(time.Duration(20+w.Rand.IntN(25)) * 24 * time.Hour)
		at = clamp(w, w.WorkHours(at, o.Loc))
		actor := by(o, at, world.RoleITAdmin, world.RoleAdmin)
		w.At(at, func() { s.api.do(o, actor, "", "PUT", path+"/retention", p) })
	}
}
