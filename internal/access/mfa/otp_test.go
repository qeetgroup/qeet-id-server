package mfa

import (
	"testing"

	"github.com/google/uuid"
)

// TestOTPMessageTemplate checks that only an emailed sign-in code names the
// organization's mfa_otp template.
func TestOTPMessageTemplate(t *testing.T) {
	organization := uuid.New()
	for _, test := range []struct {
		name         string
		in           otpSend
		templated    bool
		organization string
	}{
		{"emailed sign-in code", otpSend{organizationID: &organization, channel: "email", purpose: "sign_in"}, true, organization.String()},
		{"SMS sign-in code", otpSend{organizationID: &organization, channel: "sms", purpose: "sign_in"}, false, ""},
		{"step-up code", otpSend{organizationID: &organization, channel: "email", purpose: "step_up"}, false, ""},
		{"enrollment code", otpSend{organizationID: &organization, channel: "email", purpose: "enrollment"}, false, ""},
		{"sign-in with no organization", otpSend{channel: "email", purpose: "sign_in"}, false, ""},
	} {
		m := test.in.message("Qeet ID", "123456")
		if (m.TemplateKey == "mfa_otp") != test.templated || m.OrganizationID != test.organization {
			t.Errorf("%s: template %q of organization %q; want templated %v of %q", test.name, m.TemplateKey, m.OrganizationID, test.templated, test.organization)
		}
		if test.templated && (m.TemplateVariables["code"] != "123456" || m.TemplateVariables["ttl"] != "10 minutes") {
			t.Errorf("%s: values %v, want the code and its lifetime", test.name, m.TemplateVariables)
		}
		if m.Body == "" || m.Subject == "" {
			t.Errorf("%s: no platform wording to fall back on: %+v", test.name, m)
		}
	}
}
