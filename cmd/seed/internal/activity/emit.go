package activity

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// otpFactor is a person's verified email or SMS second factor.
type otpFactor struct {
	id                   uuid.UUID
	channel, destination string
}

// emit writes what the API records around a sign-in: wrong passwords first,
// the sign-in link for a magic-link sign-in, the second-factor challenge and
// any code sent, then auth.login_succeeded and the sign-in's device and
// country for the risk engine.
func (h *history) emit(s *session) {
	w := h.w
	p, o, t := s.p, s.org, s.created
	organization := ptr(o.ID)
	if s.first == "tenant_switch" {
		h.audit(t, audit.Event{OrganizationID: organization, ActorUserID: ptr(p.ID), ActorType: "user", Action: "auth.login_succeeded",
			ResourceType: "session", ResourceID: ptr(s.id), IP: s.dev.IP, UserAgent: s.dev.UserAgent,
			Metadata: map[string]any{"method": "tenant_switch", "previous_session_id": s.previous.id, "second_factor": s.factor}})
		return
	}
	// The first factor, before any challenge.
	proved := t.Add(-jitter(w, 0.4, 1.2))
	for i := range s.typos {
		method := "password"
		if s.first == "ldap" {
			method = "ldap"
		}
		h.failure(o, p, s.dev, proved.Add(-time.Duration(i+1)*jitter(w, 0.3, 0.7)), method, "wrong_password")
	}
	if s.first == "magic_link" {
		app := ""
		if o.Spec.Features.SelfSignup || s.dev.Kind != "desktop" {
			app = "hosted_login"
		}
		asked := proved.Add(-jitter(w, 0.5, 3))
		h.audit(asked, audit.Event{OrganizationID: ptr(p.Org.ID), ActorType: "anonymous", Action: "auth.magic_link_requested",
			ResourceType: "user", ResourceID: ptr(p.ID), IP: s.dev.IP, UserAgent: s.dev.UserAgent, Metadata: map[string]any{"app": app}})
		h.mail(organization, p.Email, "magic_link", asked.Add(time.Second))
		h.audit(proved, audit.Event{OrganizationID: organization, ActorUserID: ptr(p.ID), ActorType: "system", Action: "auth.magic_link_consumed",
			ResourceType: "user", ResourceID: ptr(p.ID), IP: s.dev.IP, UserAgent: s.dev.UserAgent, Metadata: map[string]any{"app": app}})
	}
	if c := h.challenge(o, p, s); c != nil {
		h.audit(proved.Add(time.Second), audit.Event{OrganizationID: organization, ActorUserID: ptr(p.ID), ActorType: "user",
			Action: "auth.mfa_challenged", ResourceType: "user", ResourceID: ptr(p.ID), IP: s.dev.IP, UserAgent: s.dev.UserAgent,
			Metadata: c})
		if f, ok := h.otp[p.ID]; ok && strings.HasSuffix(s.method, "_mfa") && !p.HasFactor("totp") {
			h.audit(proved.Add(2*time.Second), audit.Event{OrganizationID: organization, ActorUserID: ptr(p.ID), ActorType: "user",
				Action: "mfa.otp_sent", ResourceType: "mfa_factor", ResourceID: ptr(f.id),
				Metadata: map[string]any{"channel": f.channel, "destination": maskDestination(f.channel, f.destination), "purpose": "sign_in"}})
			if f.channel == "email" {
				h.mail(nil, f.destination, "", proved.Add(2*time.Second))
			}
		}
		if strings.HasSuffix(s.method, "_mfa") && w.Chance(0.03) {
			h.failure(o, p, s.dev, t.Add(-jitter(w, 0.1, 0.3)), "mfa", "code_invalid")
		}
	}
	h.audit(t, audit.Event{OrganizationID: organization, ActorUserID: ptr(p.ID), ActorType: "user", Action: "auth.login_succeeded",
		ResourceType: "session", ResourceID: ptr(s.id), IP: s.dev.IP, UserAgent: s.dev.UserAgent,
		Metadata: map[string]any{"method": s.method}})
	h.contexts = append(h.contexts, signInContext{organization: o.ID, user: p.ID, deviceKey: deviceKey(s.dev.UserAgent), country: s.dev.Country, seen: t})
}

// challenge is the metadata of the second-factor challenge a sign-in met, or
// nil when it met none: the factors p held, or enrolment when p had none yet
// and o requires one.
func (h *history) challenge(o *world.Org, p *world.Person, s *session) map[string]any {
	switch s.first {
	case "password", "magic_link", "social", "ldap":
	default:
		return nil
	}
	required := mfaRequired(o, p)
	enrolled := hasMFA(p, s.created)
	if !enrolled && !required {
		return nil
	}
	reason := "enrolled"
	switch {
	case required && o.Spec.Features.MFA == "required":
		reason = "tenant_required"
	case required:
		reason = "admin_required"
	}
	meta := map[string]any{"reason": reason, "enrollment": !enrolled, "first_factor": s.first, "methods": []string{"totp"}}
	if enrolled {
		meta["methods"] = challengeMethods(p)
	} else if o.Spec.Features.MFAGrace > 0 {
		meta["grace_until"] = o.Spec.Since.Add(time.Duration(o.Spec.Features.MFAGrace) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}
	return meta
}

// challengeMethods are the second factors a challenge offers p, in the
// order the MFA service lists them.
func challengeMethods(p *world.Person) []string {
	var out []string
	for _, f := range []struct{ factor, method string }{
		{"totp", "totp"}, {"recovery", "recovery_code"}, {"email", "email"}, {"sms", "sms"}, {"passkey", "passkey"}, {"push", "push"},
	} {
		if p.HasFactor(f.factor) {
			out = append(out, f.method)
		}
	}
	return out
}

// maskDestination masks an email address or phone number as the MFA service
// does in its records.
func maskDestination(channel, dest string) string {
	if channel == "email" {
		at := strings.IndexByte(dest, '@')
		if at <= 1 {
			return dest
		}
		return dest[:1] + strings.Repeat("*", at-1) + dest[at:]
	}
	if len(dest) <= 3 {
		return dest
	}
	return strings.Repeat("*", len(dest)-3) + dest[len(dest)-3:]
}

// deviceKey reduces a user agent to the browser and system pair the risk
// engine remembers devices by, as its deviceKey does.
func deviceKey(ua string) string {
	u := strings.ToLower(ua)
	browser := "other"
	switch {
	case strings.Contains(u, "edg/"):
		browser = "edge"
	case strings.Contains(u, "chrome/"):
		browser = "chrome"
	case strings.Contains(u, "firefox/"):
		browser = "firefox"
	case strings.Contains(u, "safari/"):
		browser = "safari"
	}
	os := "other"
	switch {
	case strings.Contains(u, "windows"):
		os = "windows"
	case strings.Contains(u, "iphone"), strings.Contains(u, "ipad"):
		os = "ios"
	case strings.Contains(u, "mac os"):
		os = "macos"
	case strings.Contains(u, "android"):
		os = "android"
	case strings.Contains(u, "linux"):
		os = "linux"
	}
	return browser + "-" + os
}
