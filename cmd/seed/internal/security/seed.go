// Package security seeds people's second factors and sign-ins, and each
// organization's security posture: address rules, risk and bot settings, the
// attacks on it, audit-anomaly settings, compliance evidence and service
// incidents.
package security

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/totp"
)

// Seed enrols factors, signs people in and sets every organization's
// security posture.
func Seed(w *world.World) {
	s := &state{w: w}
	enrolAll(w)
	for _, o := range w.Orgs {
		addressRules(w, o)
		threatSettings(w, o)
	}
	for _, o := range w.Orgs {
		for _, p := range o.Active() {
			s.signIn(p)
		}
	}
	for _, o := range w.Orgs {
		s.attacks(o)
	}
	evidence(w)
	salesLeads(w)
	s.summary()
}

// state counts what the sign-ins and attacks did, for the summary.
type state struct {
	w                             *world.World
	sessions, challenged, refused int
	demos                         []string
}

// enrolAll sets up everyone's planned second factors, a few at a time:
// minting and hashing recovery codes is most of the seed's work. The test
// accounts' secrets go in the summary.
func enrolAll(w *world.World) {
	var todo []*world.Person
	phones := map[*world.Person]phone{}
	for _, o := range w.Orgs {
		for _, p := range o.People {
			if len(p.MFA) > 0 && p.Status != world.StatusDeleted {
				todo = append(todo, p)
				if p.HasFactor("push") {
					phones[p] = newPhone(w, p)
				}
			}
		}
	}
	next := make(chan *world.Person)
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for p := range next {
				enrol(w, p, phones[p])
			}
		})
	}
	for _, p := range todo {
		next <- p
	}
	close(next)
	wg.Wait()
	const section = "Second factors for test accounts (add the secret to any authenticator app)"
	for _, p := range todo {
		if p.Login != "" {
			w.Note(section, "%-38s %s", p.Email, p.TOTPSecret)
			w.Note(section, "  %s", totp.ProvisioningURL(p.TOTPSecret, w.Cfg.JWTIssuer, p.Email))
		}
	}
	if aarav := w.Person("aarav@qeet.in"); len(aarav.RecoveryCodes) > 0 {
		w.Note(section, "Recovery codes for %s (each works once): %s", aarav.Email, strings.Join(aarav.RecoveryCodes, " "))
	}
}

// phone is a person's phone as the Qeet ID app links it for push approval:
// an APNs device token from an iPhone, an FCM registration token otherwise.
type phone struct{ name, platform, token string }

func newPhone(w *world.World, p *world.Person) phone {
	if strings.Contains(p.Mobile.UserAgent, "iPhone") {
		return phone{p.First + "’s iPhone", "ios", w.Token(world.Hex, 64)}
	}
	return phone{"Android phone", "android", w.Token(world.Alnum+"-_", 22) + ":APA91b" + w.Token(world.Alnum+"-_", 134)}
}

// enrol sets up p's authenticator app and recovery codes, and links ph when
// p has one, through the MFA service as the account screens do.
func enrol(w *world.World, p *world.Person, ph phone) {
	svc := w.Deps.MFA.Service
	by := mfa.Caller{Actor: audit.Actor{UserID: &p.ID, Type: "user", IP: p.Device.IP, UserAgent: p.Device.UserAgent},
		OrganizationID: &p.Org.ID}
	started, err := svc.StartEnroll(w.Ctx, p.ID, p.Email, by)
	w.Check(err, "start TOTP for "+p.Email)
	code, err := totp.Code(started.Secret, time.Now())
	w.Check(err, "compute a TOTP code")
	p.RecoveryCodes, err = svc.ConfirmEnroll(w.Ctx, p.ID, code, by)
	w.Check(err, "confirm TOTP for "+p.Email)
	p.TOTPSecret = started.Secret
	if ph.token != "" {
		_, _, err := svc.RegisterPushDevice(w.Ctx, p.ID, ph.name, ph.token, ph.platform)
		w.Check(err, "link the phone of "+p.Email)
	}
	// After the second factor the browser is remembered, where the
	// organization's sign-in policy allows it.
	_, _, err = w.Deps.Auth.Service.MaybeRememberDevice(w.Ctx, p.ID, p.Org.ID, p.Device.Label)
	w.Check(err, "remember the browser of "+p.Email)
}

// signIn signs p in with their password through the auth service, meeting an
// authenticator challenge with the app's next code. A sign-in the risk engine
// or an address rule stops stays stopped; someone whose domain requires single
// sign-on would use the identity provider, which the seed can't.
func (s *state) signIn(p *world.Person) {
	w := s.w
	if p.Unverified || w.Deps.DomainVerify.Service.RefuseCaptured(w.Ctx, p.Email) != nil {
		return
	}
	res, err := w.Deps.Auth.Service.Login(w.Ctx, authentication.LoginInput{Email: p.Email, Password: w.Password, IP: p.Device.IP, UserAgent: p.Device.UserAgent})
	switch {
	case err != nil:
		s.refused++
		return
	case res.Pair != nil:
		s.sessions++
		return
	case p.TOTPSecret == "" || res.EnrollmentRequired:
		s.challenged++
		return
	}
	code, err := totp.Code(p.TOTPSecret, time.Now().Add(30*time.Second))
	w.Check(err, "compute a TOTP code")
	if _, err := w.Deps.Auth.Service.CompleteMFALogin(w.Ctx, res.MFAToken, code, p.Device.IP, p.Device.UserAgent); err != nil {
		s.refused++ // Kestrel's address rules refuse sign-in from home, after the second factor
		return
	}
	s.sessions++
}

// wrongPasswords are what credential lists and sprays try.
var wrongPasswords = []string{"Welcome@123", "Password@2026", "Summer2026!", "Qwerty@123", "India@123", "Admin@1234", "P@ssw0rd1"}

// attacks runs wrong passwords at the organization through the auth service,
// so locks, throttles, security events and alerts are the server's own:
// credential stuffing that locks one account, and at Northwind and Meridian a
// spray that throttles its source. The bot check scores each attempt.
func (s *state) attacks(o *world.Org) {
	w, cfg := s.w, authentication.DefaultLockoutConfig()
	var ordinary []*world.Person
	for _, p := range o.Active() {
		if p.Login == "" && !p.Unverified {
			ordinary = append(ordinary, p)
		}
	}
	try := func(src world.Device, p *world.Person, i int) {
		w.Deps.Bot.Service.Evaluate(w.Ctx, p.Email, src.IP, src.UserAgent)
		_, err := w.Deps.Auth.Service.Login(w.Ctx, authentication.LoginInput{Email: p.Email, Password: wrongPasswords[i%len(wrongPasswords)],
			IP: src.IP, UserAgent: src.UserAgent})
		if err == nil {
			w.Check(errors.New("an attacker's password was accepted"), "attack "+p.Email)
		}
	}
	stuffed := map[string]world.Device{"northwind": world.Attackers[0], "meridian": world.Attackers[0], "lumen": world.Attackers[2], "qeet": world.Attackers[1]}
	if src, ok := stuffed[o.Spec.Slug]; ok && len(ordinary) > 0 {
		victim := ordinary[len(ordinary)/2]
		for i := range cfg.Defaults.Threshold + 1 {
			try(src, victim, i)
		}
		s.demos = append(s.demos, fmt.Sprintf("Lockout: %s (%s) locked by wrong passwords from %s — open credential_stuffing event, alert in their bell",
			victim.Email, o.Spec.Name, src.IP))
	}
	if (o.Spec.Slug == "northwind" || o.Spec.Slug == "meridian") && len(ordinary) > cfg.SourceAccounts {
		src := world.Attackers[3]
		for i, p := range ordinary[:cfg.SourceAccounts+1] {
			try(src, p, i)
		}
		s.demos = append(s.demos, fmt.Sprintf("Spraying: %s throttled after failing against %d %s accounts — open password_spraying event",
			src.IP, cfg.SourceAccounts, o.Spec.Name))
	}
}

// summary adds the step's notes.
func (s *state) summary() {
	const section = "Security and sign-ins"
	s.w.Note(section, "%d sessions from password sign-ins just now; %d stopped at an email-code or enrolment challenge, %d refused by address rules",
		s.sessions, s.challenged, s.refused)
	s.w.Note(section, "IP allowlist: every Kestrel member, %s included, is refused from localhost; Northwind enforces deny rules only;",
		s.w.Org("kestrel").Owner.Email)
	s.w.Note(section, "  Qeet Group keeps an office allowlist staged, switched off")
	for _, d := range s.demos {
		s.w.Note(section, "%s", d)
	}
}
